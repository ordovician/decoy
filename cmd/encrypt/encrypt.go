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

	"log"
)

var (
	DebugLog *log.Logger
	WarnLog  *log.Logger
	InfoLog  *log.Logger
	ErrorLog *log.Logger
)

// Called first in any package
func init() {
	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	// Make it possible to have different log levels
	// Edit to have file as output for what you want to log and use io.Discard to turn off logging
	DebugLog = log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLog = log.New(io.Discard, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarnLog = log.New(io.Discard, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLog = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	// Parse command line arguments
	var encodingStr string // how we encode the generated key
	var keyFilename string // file containing the decryption key

	flag.StringVar(&encodingStr, "encoding", "hex", "Encoding used to store key. Could be hex, base32, base64 or pem")
	flag.StringVar(&keyFilename, "key", "key.pem", "File storing the encryption key")

	flag.Parse()

	InfoLog.Printf("Opening keyfile: %s", keyFilename)
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

	InfoLog.Printf("Reading message file: %s", flag.Arg(0))
	message, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	InfoLog.Printf("Encrypting read message")
	ciphertext, err := encrypt(key, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	encoding := base32.StdEncoding
	encodedCiphertext := make([]byte, encoding.EncodedLen(len(ciphertext)))
	encoding.Encode(encodedCiphertext, ciphertext)

	DebugLog.Printf("len(encodedCiphertext) = %d", len(encodedCiphertext))
	fmt.Printf("%s", encodedCiphertext)
}

// DecodeKey used for encryption by reading from reader assuming it is stored
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
	if len(plaintext)%aes.BlockSize != 0 {
		nblocks := 1 + len(plaintext)/aes.BlockSize
		msg = make([]byte, nblocks*aes.BlockSize)
		copy(msg, plaintext)
	} else {
		msg = plaintext
	}

	DebugLog.Printf("len(msg) = %d", len(msg))

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return empty, err
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCEncrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return ciphertext, nil
}
