package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

//go:embed key.base64.txt
var cryptKey string

// Load key to decrypt data from key.base64.txt
// The key must be stored in base64 format.
func loadKey() (key []byte, err error) {
	keyReader := strings.NewReader(cryptKey)
	var decoder io.Reader = base64.NewDecoder(base64.StdEncoding, keyReader)

	key, err = io.ReadAll(decoder)
	if err != nil {
		err = fmt.Errorf("Unable to decode encryption key file: %w", err)
	}
	return
}

// Decrypt contents of file with filename using AES algorithm operating in block chaining mode
// We assume the encrypted data is stored on file in base32 encoding
func decryptFile(key []byte, filename string) (message string, err error) {
	filepath := path.Join("data", filename)
	file, err := storage.Open(filepath)
	if err != nil {
		err = fmt.Errorf("Could not open encrypted file %s: %w", filename, err)
		return
	}
	defer file.Close()

	var decoder io.Reader = base32.NewDecoder(base32.StdEncoding, file)

	ciphertext, err := io.ReadAll(decoder)
	if err != nil {
		err = fmt.Errorf("Unable to decode encryption key file: %w", err)
	}

	message, err = decryptBytes(key, ciphertext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt %s: %v\n", filename, err)
		os.Exit(1)
	}
	return
}

// decrypt a message using decryption key with AES algorithm operating in block chaining mode
func decryptBytes(key []byte, ciphertext []byte) (message string, err error) {
	var (
		block cipher.Block // An encrypter or decrypter for an individual block
	)
	block, err = aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("Unable to decrypt ciphertext: %w", err)
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = fmt.Errorf("ciphertext too short. Needs to be larger than a block")
		return
	}

	// The initialization vector is the first block. Also called a nonce. This
	// works a little bit like a salt. It is not secret but adds randomness so the same
	// data does not get encrypted the same way repeatedly.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// In cipher-block chaining (CBC) mode we always work with whole blocks,
	// not partial blocks
	if len(ciphertext)%aes.BlockSize != 0 {
		err = fmt.Errorf("ciphertext not a multiple of the AES block size")
		return
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	message = string(ciphertext)
	return
}
