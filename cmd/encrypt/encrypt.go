package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
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
	fmt.Printf("%s", ciphertext)
}

func DecodeKey(reader io.Reader, encodingStr string) ([]byte, error) {
	if encodingStr == "pem" {

	}

	return []byte{}, nil
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

	// In cipher-block chaining (CBC) mode we always work with whole blocks,
	// not partial blocks
	if len(plaintext)%aes.BlockSize != 0 {
		return empty, fmt.Errorf("plaintext not a multiple of the AES block size")
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return empty, err
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCEncrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}
