package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// Main function demonstrating AES encryption and RSA digital signatures
func main() {
	// Retrieve AES key from environment variable
	aesKey := os.Getenv("AES_KEY")
	if aesKey == "" {
		fmt.Println("AES_KEY environment variable not set")
		return
	}

	message := "Hello, Crypto Agile!"
	fmt.Printf("Original Message: %s\n", message)

	// Encrypt the message with AES
	encrypted, err := encryptAES([]byte(message), aesKey)
	if err != nil {
		fmt.Printf("Error encrypting message: %v\n", err)
		return
	}
	fmt.Printf("Encrypted Message: %s\n", hex.EncodeToString(encrypted))

	// Calculate the hash of the encrypted message
	hashed := calculateHash(encrypted)
	fmt.Printf("SHA-256 Hash: %s\n", hashed)

	// Generate RSA key pair
	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		fmt.Printf("Error generating RSA key pair: %v\n", err)
		return
	}

	// Sign the hash with RSA private key
	signature, err := signRSA([]byte(hashed), privateKey)
	if err != nil {
		fmt.Printf("Error signing hash: %v\n", err)
		return
	}
	fmt.Printf("RSA Signature: %s\n", hex.EncodeToString(signature))

	// Verify the signature with RSA public key
	valid := verifyRSA([]byte(hashed), signature, publicKey)
	fmt.Printf("Signature Verification: %v\n", valid)
}

// Encrypts plaintext using AES with the provided key
func encryptAES(plaintext []byte, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("could not create cipher block: %v", err)
	}

	// Pad plaintext to be a multiple of AES block size (16 bytes)
	plaintext = pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("could not generate IV: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// Pads the input to be a multiple of the block size
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// Unpads the input to remove the padding
func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// Calculates the SHA-256 hash of the input
func calculateHash(input []byte) string {
	hasher := sha256.New()
	hasher.Write(input)
	hashed := hasher.Sum(nil)
	return hex.EncodeToString(hashed)
}

// Generates an RSA key pair
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate RSA key pair: %v", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

// Signs the input message using RSA with the provided private key
func signRSA(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("could not sign message: %v", err)
	}
	return signature, nil
}

// Verifies the RSA signature of the input message
func verifyRSA(message, signature []byte, publicKey *rsa.PublicKey) bool {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}
