package main

import (
	"crypto/aes"
	"crypto/cipher"
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

func main() {
	// To disable log output. Used when we are not debugging the code
	log.SetOutput(io.Discard)

	var encodingStr string // how we encode the generated key
	var keyFilename string // file containing the decryption key

	flag.StringVar(&encodingStr, "encoding", "hex", "Encoding used to store key. Could be hex, base32, base64 or pem")
	flag.StringVar(&keyFilename, "key", "key.pem", "File storing the decryption key")

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
		os.Exit(1)
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "You need to provide the name of a file to decrypt")
		os.Exit(1)
	}

	encodedText, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	ciphertext := make([]byte, base32.StdEncoding.DecodedLen(len(encodedText)))
	n, err := base32.StdEncoding.Decode(ciphertext, encodedText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not decode base32 encoded encrypted text:", err)
		os.Exit(1)
	}
	// The decoded cipher text is only n character long, so cut it short otherwise you
	// include padded zeros. DecodedLen is not the actual length, just a minimum length required
	ciphertext = ciphertext[:n]

	log.Printf("len(ciphertext) = %d", len(ciphertext))

	message, err := decrypt(key, ciphertext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	fmt.Printf("%s", message)
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

// decrypt a message using decryption key with AES algorithm operating in block chaining mode
func decrypt(key []byte, ciphertext []byte) (string, error) {
	var (
		block cipher.Block // An encrypter or decrypter for an individual block
		err   error
	)
	block, err = aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Unable to decrypt ciphertext: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short. Needs to be larger than a block")
	}

	// The initialization vector is the first block. Also called a nonce. This
	// works a little bit like a salt. It is not secret but adds randomness so the same
	// data does not get encrypted the same way repeatedly.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// In cipher-block chaining (CBC) mode we always work with whole blocks,
	// not partial blocks
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not a multiple of the AES block size")
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return string(ciphertext), nil
}
