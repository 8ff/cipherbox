package cc2p1305_scrypt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

type Params struct {
	SaltSize  int
	NonceSize int
	KeySize   int
	Key       []byte
}

// Sane defaults
var ParamDefaults = Params{
	SaltSize:  32,
	NonceSize: chacha20poly1305.NonceSizeX,
	KeySize:   chacha20poly1305.KeySize,
}

// Encrypt function based on chacha20poly1305 and scrypt
func (c *Params) Encrypt(data []byte) ([]byte, error) {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return nil, fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	// Check if data is bigger than Uint32
	if uint32(len(data)) > ^uint32(0) {
		return nil, fmt.Errorf("data chunk is too big, max size is : %d bytes", ^uint32(0))
	}

	// Generate a random key salt
	keySalt := make([]byte, c.SaltSize)
	if _, err := rand.Read(keySalt); err != nil {
		return nil, fmt.Errorf("error generating key salt: %s", err)
	}

	// Hash the key with the salt
	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("error hashing key: %s", err)
	}

	// Create a buffer to hold the encrypted data
	chunk := make([]byte, 0)
	aead, err := chacha20poly1305.NewX(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %s", err)
	}

	// Generate a random nonce
	nonce := make([]byte, c.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %s", err)
	}
	chunk = append(chunk, nonce...)
	chunk = append(chunk, keySalt...)
	chunk = append(chunk, aead.Seal(nil, nonce, data, nil)...)

	// Calculate chunkSize of chunk and Prepend chunkSize to chunk
	chunkSize := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkSize, uint32(len(chunk[:])))
	// Prepends chunkSize to chunk
	chunk = append(chunkSize, chunk...)

	return chunk, nil
}

// Decrypt function based on chacha20poly1305 and scrypt
func (c *Params) Decrypt(data []byte) ([]byte, error) {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return nil, fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	// Check if data is bigger than Uint32
	chunkSize := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data[4:])) != chunkSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce := data[4 : 4+c.NonceSize]
	keySalt := data[4+c.NonceSize : 4+c.NonceSize+c.SaltSize]
	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("error hashing key: %s", err)
	}

	// Create a buffer to hold the encrypted data
	aead, err := chacha20poly1305.NewX(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %s", err)
	}

	// Decrypt the data
	decrypted, err := aead.Open(nil, nonce, data[4+c.NonceSize+c.SaltSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %s", err)
	}
	return decrypted, nil
}

// StreamEncrypt function based on chacha20poly1305 and scrypt
func (c *Params) StreamEncrypt(r io.Reader, w io.Writer, chunkSize int) error {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	// Generate a random key salt
	keySalt := make([]byte, c.SaltSize)
	if _, err := rand.Read(keySalt); err != nil {
		return fmt.Errorf("error generating key salt: %s", err)
	}

	// Write the key salt to the writer
	if _, err := w.Write(keySalt); err != nil {
		return fmt.Errorf("error writing key salt: %s", err)
	}

	// Hash the key with the salt
	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("error hashing key: %s", err)
	}

	// Create a buffer to hold the encrypted data
	aead, err := chacha20poly1305.NewX(hashedKey[:])
	if err != nil {
		return fmt.Errorf("error creating aead: %s", err)
	}

	// Generate a random nonce
	nonce := make([]byte, c.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generating nonce: %s", err)
	}
	if _, err := w.Write(nonce); err != nil {
		return fmt.Errorf("error writing nonce: %s", err)
	}

	// Encrypt and write the data in chunks
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading data: %s", err)
		}
		if n == 0 {
			break
		}

		// Create a buffer to hold the encrypted data
		encBuf := make([]byte, n+aead.Overhead())
		aead.Seal(encBuf[:0], nonce, buf[:n], nil)

		// Write the encrypted data to the writer
		if _, err := w.Write(encBuf); err != nil {
			return fmt.Errorf("error writing encrypted data: %s", err)
		}
	}

	return nil
}

// StreamDecrypt function based on chacha20poly1305 and scrypt
func (c *Params) StreamDecrypt(r io.Reader, w io.Writer, chunkSize int) error {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	// Read the key salt from the reader
	keySalt := make([]byte, c.SaltSize)
	if _, err := io.ReadFull(r, keySalt); err != nil {
		return fmt.Errorf("error reading key salt: %s", err)
	}

	// Read the nonce from the reader
	nonce := make([]byte, c.NonceSize)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return fmt.Errorf("error reading nonce: %s", err)
	}

	// Hash the key with the salt
	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("error hashing key: %s", err)
	}

	// Create a buffer to hold the encrypted data
	aead, err := chacha20poly1305.NewX(hashedKey[:])
	if err != nil {
		return fmt.Errorf("error creating aead: %s", err)
	}

	// Decrypt the data in chunks
	buf := make([]byte, chunkSize+aead.Overhead())
	for {
		// Read the encrypted data for the chunk from the reader
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading encrypted data: %s", err)
		}
		if n == 0 {
			break
		}

		// Decrypt the chunk and write it to the output writer
		decBuf, err := aead.Open(nil, nonce, buf[:n], nil)
		if err != nil {
			return fmt.Errorf("error decrypting data: %s", err)
		}
		if _, err := w.Write(decBuf); err != nil {
			return fmt.Errorf("error writing decrypted data: %s", err)
		}
	}

	return nil
}

func Init(params Params) (*Params, error) {
	// Go over all params and if unset set them to defaults
	if params.SaltSize == 0 {
		params.SaltSize = ParamDefaults.SaltSize
	}

	if params.NonceSize == 0 {
		params.NonceSize = ParamDefaults.NonceSize
	}

	if params.KeySize == 0 {
		params.KeySize = ParamDefaults.KeySize
	}

	// Return error if key is not set
	if params.Key == nil {
		return nil, fmt.Errorf("key is not set")
	}

	return &params, nil
}
