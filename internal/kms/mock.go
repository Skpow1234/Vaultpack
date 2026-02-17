package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// MockProvider is an in-memory KMS for tests. It uses a fixed key to wrap/unwrap DEKs.
// Key ID is the string "mock-key-id"; the same instance must be used for wrap and unwrap.
type MockProvider struct {
	wrapKey []byte
	keyID   string
	mu      sync.Mutex
}

// NewMockProvider creates a mock KMS provider. wrapKey must be 32 bytes (AES-256).
// If wrapKey is nil, a random key is generated (single use: wrap and unwrap in the same process).
func NewMockProvider(wrapKey []byte) *MockProvider {
	if len(wrapKey) == 0 {
		wrapKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, wrapKey); err != nil {
			panic("mock kms: " + err.Error())
		}
	}
	if len(wrapKey) != 32 {
		panic("mock kms: wrap key must be 32 bytes")
	}
	return &MockProvider{wrapKey: wrapKey, keyID: MockKeyID}
}

// WrapDEK encrypts the DEK with the mock key. keyID is ignored (mock uses fixed key).
func (m *MockProvider) WrapDEK(plainDEK []byte, keyID string) (wrapped []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	block, err := aes.NewCipher(m.wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plainDEK, []byte("vaultpack-mock-kms"))
	return ciphertext, nil
}

// UnwrapDEK decrypts the wrapped DEK. keyID must be "mock-key-id".
func (m *MockProvider) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	if keyID != m.keyID {
		return nil, fmt.Errorf("mock kms: key ID mismatch")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	block, err := aes.NewCipher(m.wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("mock kms: ciphertext too short")
	}
	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, []byte("vaultpack-mock-kms"))
}

// MockKeyID is the key ID string used by MockProvider (for manifest storage).
const MockKeyID = "mock-key-id"

// Fixed key for the default "mock" provider so that protect and decrypt in separate invocations can round-trip.
var mockFixedKey [32]byte

func init() {
	Register("mock", NewMockProvider(mockFixedKey[:]))
}
