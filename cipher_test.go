package cipher

import (
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
