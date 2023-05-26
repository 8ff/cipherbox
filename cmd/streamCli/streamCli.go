package main

import (
	"fmt"
	"os"

	cipher "github.com/8ff/cipherbox/pkg/cc2p1305_scrypt"
)

func main() {
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

	// Check command line arguments
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: cipherCli e|d\n")
		os.Exit(1)
	}

	// Encrypt or decrypt data based on command line argument
	switch os.Args[1] {
	case "e":
		if err := c.StreamEncrypt(os.Stdin, os.Stdout, 1024); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encrypt data: %v\n", err)
			os.Exit(1)
		}
	case "d":
		if err := c.StreamDecrypt(os.Stdin, os.Stdout, 1024); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt data: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage: cipherCli e|d")
		os.Exit(1)
	}
}
