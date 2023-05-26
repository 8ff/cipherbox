package cc2p1305_scrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Test encrypt and decrypt with random data input and key and verify that the decrypted data is the same as the original data
func TestEncryptDecrypt(t *testing.T) {
	data := make([]byte, 3200)
	key := make([]byte, ParamDefaults.KeySize)
	rand.Read(data)
	rand.Read(key)

	c, err := Init(Params{Key: key})
	if err != nil {
		t.Errorf("Failed to initialize cipher: %v", err)
	}

	encrypted, err := c.Encrypt(data)
	if err != nil {
		t.Errorf("Failed to encrypt data: %v", err)
	}
	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Failed to decrypt data: %v", err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decrypted data is not the same as original data")
	}
}

// Test stream encrypt and decrypt with random data input and key and verify that the decrypted data is the same as the original data
func TestStreamEncryptDecrypt(t *testing.T) {
	data := make([]byte, 320000)
	key := make([]byte, ParamDefaults.KeySize)
	rand.Read(data)
	rand.Read(key)

	c, err := Init(Params{Key: key})
	if err != nil {
		t.Errorf("Failed to initialize cipher: %v", err)
	}

	var buf bytes.Buffer
	if err := c.StreamEncrypt(bytes.NewReader(data), &buf, 1024*10); err != nil {
		t.Errorf("Failed to stream encrypt data: %v", err)
	}

	decryptedBuf := bytes.NewBuffer(nil)
	if err := c.StreamDecrypt(&buf, decryptedBuf, 1024*10); err != nil {
		t.Errorf("Failed to stream decrypt data: %v", err)
	}

	decrypted := decryptedBuf.Bytes()
	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decrypted data is not the same as original data")
	}
}
