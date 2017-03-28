package rtea

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("ohmygoshOHMYGOSH")
	c, err := NewCipher(key)
	if err != nil {
		t.Error(err)
		return
	}

	plaintext := []byte("TWILIGHT")
	ciphertext := make([]byte, len(plaintext))
	c.Encrypt(ciphertext, plaintext)
	c.Decrypt(ciphertext, ciphertext)
	if !bytes.Equal(ciphertext, plaintext) {
		t.Error("Decryption failed")
	}
}
