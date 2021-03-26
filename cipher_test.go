package cipher

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key, _ := GenerateKey(16)
	cip, _ := NewCipher(key)

	msg := "hello world"

	ciphertext, _ := cip.Encrypt([]byte(msg))
	plaintext, _ := cip.Decrypt(ciphertext)

	s := string(plaintext)

	if msg != s {
		t.Errorf("plaintext = '%s'; want '%s'\n", plaintext, msg)
	}
}

// Test that two generated keys are different
func TestGenerateRandomKey(t *testing.T) {
	first, _ := GenerateKey(32)
	second, _ := GenerateKey(32)

	if first == second {
		t.Errorf("Two randomly generated keys should not be identical!")
	}
}

// Test saving and loading a key. Make sure we get the same back
// as we put in
func TestKeyGenerationRoundTrip(t *testing.T) {
	var keystorage bytes.Buffer

	key, _ := GenerateKey(16)
	key.Save(&keystorage)

	loadedKey, _ := LoadKey(&keystorage)
	if bytes.Compare(key.Bytes, loadedKey.Bytes) != 0 {
		t.Errorf("Stored key not equal loaded key")
	}
}
