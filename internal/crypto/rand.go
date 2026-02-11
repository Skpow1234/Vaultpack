package crypto

import (
	"crypto/rand"
	"fmt"
)

// GenerateNonce generates a cryptographically random nonce of the given size.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateKey generates a cryptographically random key of the given size in bytes.
func GenerateKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}
