package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"syscall"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

func main() {
	encryptMode := flag.Bool("e", false, "encrypt mode")
	decryptMode := flag.Bool("d", false, "decrypt mode")
	flag.Parse()

	if (*encryptMode && *decryptMode) || (!*encryptMode && !*decryptMode) {
		fmt.Println("Usage: ./encryptor -e or ./encryptor -d")
		os.Exit(1)
	}

	// Securely read password
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	password := string(bytePassword)
	fmt.Println() // Newline after password input

	if *encryptMode {
		// Read plaintext.txt
		plaintext, err := os.ReadFile("plaintext.txt")
		if err != nil {
			fmt.Println("Error reading plaintext.txt:", err)
			os.Exit(1)
		}

		// Encrypt
		ciphertextBase64, err := encrypt(plaintext, password)
		if err != nil {
			fmt.Println("Error encrypting:", err)
			os.Exit(1)
		}

		// Write to ciphertext.txt
		err = os.WriteFile("ciphertext.txt", []byte(ciphertextBase64), 0644)
		if err != nil {
			fmt.Println("Error writing ciphertext.txt:", err)
			os.Exit(1)
		}
		fmt.Println("Encryption complete. Output in ciphertext.txt")
	} else {
		// Read ciphertext.txt
		ciphertextBase64, err := os.ReadFile("ciphertext.txt")
		if err != nil {
			fmt.Println("Error reading ciphertext.txt:", err)
			os.Exit(1)
		}

		// Decode base64
		data, err := base64.StdEncoding.DecodeString(string(ciphertextBase64))
		if err != nil {
			fmt.Println("Error decoding base64:", err)
			os.Exit(1)
		}

		// Decrypt
		plaintext, err := decrypt(data, password)
		if err != nil {
			fmt.Println("Error decrypting:", err)
			os.Exit(1)
		}

		// Write to plaintext.txt
		err = os.WriteFile("plaintext.txt", plaintext, 0644)
		if err != nil {
			fmt.Println("Error writing plaintext.txt:", err)
			os.Exit(1)
		}
		fmt.Println("Decryption complete. Output in plaintext.txt")
	}
}

func encrypt(plaintext []byte, password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, 65536, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Create GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt and authenticate
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Concatenate salt, nonce, and ciphertext (which includes tag)
	output := append(salt, nonce...)
	output = append(output, ciphertext...)

	// Return base64 encoded string
	return base64.StdEncoding.EncodeToString(output), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := data[:16]
	nonce := data[16:28]
	ciphertext := data[28:]

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, 65536, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
