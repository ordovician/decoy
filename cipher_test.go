package cipher

import "testing"

func TestRoundTrip(t *testing.T) {
	key, _ := GenerateKey(5)
	cip, _ := NewCipher(key)

	msg := "hello world"

	ciphertext, _ := cip.Encrypt([]byte(msg))
	plaintext, _ := cip.Decrypt(ciphertext)

	if msg != string(plaintext) {
		t.Errorf("plaintext = %s; want %s", plaintext, msg)
	}
}
