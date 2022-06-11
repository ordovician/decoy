package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	// structured logging
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	// "log"
)

var logger *zap.Logger
var sugar *zap.SugaredLogger

// func initLogger() {
// 	logger, _ = zap.NewDevelopment()
// 	sugar = logger.Sugar()
// }

// Sets up logging to file log.json with log level DebugLevel.
// NOTE: This was  code was copied. I cannot personally make good sense of it.
// Why do we need cores, sync writers, callers. Seems like it exposes uncessesary complexity.
func initLogger() {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(config)
	logFile, _ := os.OpenFile("log.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	writer := zapcore.AddSync(logFile)
	defaultLogLevel := zapcore.DebugLevel
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, writer, defaultLogLevel),
	)
	logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	sugar = logger.Sugar()
}

func main() {
	initLogger()
	defer logger.Sync() // flushes buffer, if any

	// Parse command line arguments
	var encodingStr string // how we encode the generated key
	var keyFilename string // file containg the decryption key

	flag.StringVar(&encodingStr, "encoding", "hex", "Encoding used to store key. Could be hex, base32, base64 or pem")
	flag.StringVar(&keyFilename, "key", "key.pem", "File storing the encryption key")

	flag.Parse()

	keyFile, err := os.Open(keyFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not open encryption key file:", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	key, err := DecodeKey(keyFile, encodingStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to decode encryption key file:", err)
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "You need to provide the name of a file to encrypt")
		os.Exit(1)
	}

	message, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	ciphertext, err := encrypt(key, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	encoding := base32.StdEncoding
	encodedCiphertext := make([]byte, encoding.EncodedLen(len(ciphertext)))
	encoding.Encode(encodedCiphertext, ciphertext)

	fmt.Printf("%s", encodedCiphertext)
}

// DecodeKey used for encrypton by reading from reader assuming it is stored
// in encodingStr format.
func DecodeKey(reader io.Reader, encodingStr string) ([]byte, error) {
	if encodingStr == "pem" {
		pemData, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("Could not decode PEM data")
		}
		return block.Bytes, nil
	}

	var decoder io.Reader
	switch encodingStr {
	case "hex":
		decoder = hex.NewDecoder(reader)
	case "base32":
		decoder = base32.NewDecoder(base32.StdEncoding, reader)
	case "base64":
		decoder = base64.NewDecoder(base64.StdEncoding, reader)
	}

	return io.ReadAll(decoder)
}

// encrypt a message using decryption key with AES algorithm operating in block chaining mode
func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	var (
		block cipher.Block // An encrypter or decryptere for an individual block
		err   error
	)
	empty := make([]byte, 0)

	block, err = aes.NewCipher(key)
	if err != nil {
		return empty, fmt.Errorf("Unable to encrypt message: %w", err)
	}

	var msg []byte
	sugar.Debugw("Block allocation", "len(plaintext)", len(plaintext), "BlockSize", aes.BlockSize, "Remainder", len(plaintext)%aes.BlockSize)
	if len(plaintext)%aes.BlockSize != 0 {
		nblocks := 1 + len(plaintext)/aes.BlockSize
		msg = make([]byte, nblocks*aes.BlockSize)

		sugar.Debugw("new msg", "len(msg)", len(msg))

		copy(msg, plaintext)
	} else {
		msg = plaintext
	}

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return empty, err
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCEncrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	sugar.Debugw("Final", "len(ciphertext)", len(ciphertext))

	return ciphertext, nil
}
