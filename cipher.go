package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"os"
)

type Key struct {
	Bytes []byte
}

func GenerateKey(keyLen int) (*Key, error) {
	key := make([]byte, keyLen)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Could not generate encryption key: %w", err)
	}

	return &Key{key}, nil
}

func LoadKey(reader io.Reader) (*Key, error) {
	decoder := base32.NewDecoder(base32.StdEncoding, reader)
	bytes, err := io.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("Unable to load key: %w", err)
	}
	return &Key{bytes}, nil
}

func LoadKeyFromFile(filename string) (*Key, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Could not load key from file: %w", err)
	}
	return LoadKey(file)
}

// Save file with base32 encoding to writer
func (key *Key) Save(writer io.Writer) {
	encoder := base32.NewEncoder(base32.StdEncoding, writer)
	encoder.Write(key.Bytes)
}

// SaveToFile stores key at file name filename
func (key *Key) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Could not save cipher key: %w", err)
	}
	defer file.Close()

	key.Save(file)

	return nil
}

type Cipher struct {
	block cipher.Block
}

// New cipher for symetrical encryption
func NewCipher(key *Key) (*Cipher, error) {
	block, err := aes.NewCipher(key.Bytes)
	if err != nil {
		return nil, err
	}
	return &Cipher{block}, nil
}

// Encrypt plain text using AES encryption. Will pad if plaintext message not
// the size of an AES block
func (cip *Cipher) Encrypt(plaintext []byte) ([]byte, error) {

	var msg []byte
	if len(plaintext)%aes.BlockSize != 0 {
		nblocks := 1 + len(plaintext)/aes.BlockSize
		msg = make([]byte, nblocks*aes.BlockSize)
		copy(msg, plaintext)
	} else {
		msg = plaintext
	}

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCEncrypter(cip.block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return ciphertext, nil
}

// Decrypt cipher text using AES
func (cip *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {

	if len(ciphertext) > aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short. Needs to be larger than a block")
	}

	// The initialization vector is the first block. Also called a nonce. This
	// works a little bit like a salt. It is not secret but adds randomness so the same
	// data does not get encrypted the same way repeatedly.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// In cipher-block chaining (CBC) mode we always work with whole blocks,
	// not partial blocks
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of the AES block size")
	}

	// To allow decryption of multiple blocks, not just one
	var mode cipher.BlockMode = cipher.NewCBCDecrypter(cip.block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}
