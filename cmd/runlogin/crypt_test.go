package main

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"fmt"
	"io"
	"testing"
)

func TestReadCryptKey(t *testing.T) {
	fmt.Println(cryptKey)
	keyReader := bytes.NewBufferString(cryptKey)
	bufio.NewReader(keyReader)
	var decoder io.Reader = base32.NewDecoder(base32.StdEncoding, keyReader)

	key, err := io.ReadAll(decoder)
	if err != nil {
		t.Errorf("Failed to decode key: %v", err)
	}

	buffer := new(bytes.Buffer)
	encoder := base32.NewEncoder(base32.StdEncoding, buffer)

	encoder.Write(key)
	encoder.Close()

	gotten := buffer.String()
	if gotten != cryptKey {
		t.Errorf("Source key %s not equal re-encoded string %s", cryptKey, gotten)
	}
}

func TestDecryptKeyAsString(t *testing.T) {
	encoding := base32.StdEncoding

	keyBytes := make([]byte, encoding.DecodedLen(len(cryptKey)))
	n, err := encoding.Decode(keyBytes, []byte(cryptKey))
	if err != nil {
		t.Errorf("Could not decode base32 encoded encrypted text: %v", err)
	}

	keyBytes = keyBytes[:n]

	encodedKey := make([]byte, encoding.EncodedLen(len(keyBytes)))
	encoding.Encode(encodedKey, keyBytes)

	keyStr := string(encodedKey)
	if keyStr != cryptKey {
		t.Error("Encryption key roundtrip failed")
	}
}
