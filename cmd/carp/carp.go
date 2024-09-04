package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	cipher "github.com/8ff/cipherbox/pkg/cc2p1305_scrypt"
	"github.com/8ff/cipherbox/pkg/wipe"
)

const (
	expectedKeyLength   = 32    // Adjust based on your encryption algorithm's requirements
	fibonacciIterations = 10000 // Number of Fibonacci iterations to generate
)

func main() {
	defer handlePanic() // Ensure key is wiped even on panic

	// Display help menu if no arguments are provided or if help is requested
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		showUsageAndExit()
	}

	// Handle the command
	switch os.Args[1] {
	case "e", "d":
		key := getKeyFromEnv("CKEY")
		c, err := cipher.Init(cipher.Params{KeySize: len(key), Key: key})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize cipher: %v", err)
			os.Exit(1)
		}
		defer wipeKey(&key) // Securely wipe the key from memory after usage

		if os.Args[1] == "e" {
			if err := c.StreamEncrypt(os.Stdin, os.Stdout, 1024); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to encrypt data: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := c.StreamDecrypt(os.Stdin, os.Stdout, 1024); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decrypt data: %v\n", err)
				os.Exit(1)
			}
		}

	case "w", "wipe":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s wipe <path>\n", filepath.Base(os.Args[0]))
			os.Exit(1)
		}
		wipePath := os.Args[2]
		handleWipeCommand(wipePath)

	default:
		showUsageAndExit()
	}
}

func getKeyFromEnv(envVar string) []byte {
	key := []byte(os.Getenv(envVar))
	if len(key) == 0 {
		log.Fatalf("%s env var not set", envVar)
	}
	if len(key) < expectedKeyLength {
		key = extendKeyWithFibonacci(key, expectedKeyLength)
	}
	if len(key) != expectedKeyLength {
		log.Fatalf("Invalid key length: expected %d bytes, got %d", expectedKeyLength, len(key))
	}
	return key
}

func extendKeyWithFibonacci(key []byte, desiredLength int) []byte {
	fib := fibonacciSequence(fibonacciIterations)
	extraLength := desiredLength - len(key)

	// Take the last `extraLength` bytes from the Fibonacci sequence
	for i := len(fib) - extraLength; i < len(fib); i++ {
		key = append(key, byte(fib[i]%256))
	}
	return key
}

func fibonacciSequence(n int) []int {
	fib := make([]int, n)
	if n > 0 {
		fib[0] = 1
	}
	if n > 1 {
		fib[1] = 1
	}
	for i := 2; i < n; i++ {
		fib[i] = fib[i-1] + fib[i-2]
	}
	return fib
}

func wipeKey(data *[]byte) {
	if data != nil {
		for i := range *data {
			(*data)[i] = 0
		}
	}
}

func handlePanic() {
	if r := recover(); r != nil {
		fmt.Println("Recovered from panic, ensuring data is wiped")
		var key []byte
		wipeKey(&key)
	}
}

func handleWipeCommand(wipePath string) {
	if _, err := os.Stat(wipePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Path does not exist: %s\n", wipePath)
		os.Exit(1)
	}

	// If env var FORCE_WIPE is set, wipe the path without confirmation
	var confirm string
	if os.Getenv("FORCE_WIPE") != "true" {
		fmt.Printf("WARNING! Are you sure you want to wipe [%s]?\nType \"y\" to confirm\n", wipePath)
		fmt.Scanln(&confirm)
	} else {
		confirm = "y"
	}
	if confirm == "y" {
		if err := wipe.Wipe(wipePath, 10); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to wipe the path: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Action cancelled!")
		os.Exit(1)
	}
	os.Exit(0)
}

func showUsageAndExit() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n", binaryName)
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  e      Encrypt data from stdin to stdout (requires CKEY env var)\n")
	fmt.Fprintf(os.Stderr, "  d      Decrypt data from stdin to stdout (requires CKEY env var)\n")
	fmt.Fprintf(os.Stderr, "  wipe   Securely wipe the specified file\n")
	fmt.Fprintf(os.Stderr, "  help   Display this help menu\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  %s e < inputfile > outputfile   Encrypt inputfile and save to outputfile\n", binaryName)
	fmt.Fprintf(os.Stderr, "  %s d < inputfile > outputfile   Decrypt inputfile and save to outputfile\n", binaryName)
	fmt.Fprintf(os.Stderr, "  %s wipe /path/to/file           Securely wipe the specified file\n", binaryName)
	os.Exit(1)
}
