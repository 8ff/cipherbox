package main

import (
	"fmt"
	"io"
	"os"

	cipher "github.com/8ff/cipherbox/pkg/cc2p1305_scrypt"
)

func main() {
	// Parse args
	args := os.Args
	if len(args) != 2 {
		fmt.Println("Usage: cipherCli e|d")
		os.Exit(1)
	}
	if args[1] != "e" && args[1] != "d" {
		fmt.Println("Usage: cipherCli e|d")
		os.Exit(1)
	}

	// Read key from CKEY env var to byte slice
	key := []byte(os.Getenv("CKEY"))
	if len(key) == 0 {
		fmt.Fprintf(os.Stderr, "CKEY env var not set")
		os.Exit(1)
	}

	// Initialize cipher
	c, err := cipher.Init(cipher.Params{KeySize: len(key), Key: key})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize cipher: %v", err)
		os.Exit(1)
	}

	// Read all data from stdin
	data := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Failed to read data from stdin: %v", err)
			os.Exit(1)
		}

		data = append(data, buf[:n]...)
	}

	switch args[1] {
	case "e", "-e", "encrypt", "-encrypt", "--encrypt":
		encrypted, err := c.Encrypt(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encrypt data: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(encrypted)
	case "d", "-d", "decrypt", "-decrypt", "--decrypt":
		decrypted, err := c.Decrypt(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt data: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(decrypted)
	}
}
