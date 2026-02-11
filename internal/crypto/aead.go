package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// GCMNonceSize is the standard nonce size for AES-GCM.
	GCMNonceSize = 12
	// GCMTagSize is the standard authentication tag size for AES-GCM.
	GCMTagSize = 16
)

// EncryptResult holds the output of an AEAD encryption operation.
type EncryptResult struct {
	Ciphertext []byte // ciphertext without the tag
	Nonce      []byte
	Tag        []byte
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM with the given key.
// A random nonce is generated internally. Optional AAD can be provided.
func EncryptAESGCM(plaintext, key, aad []byte) (*EncryptResult, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidKeyLength, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Seal appends the tag to the ciphertext.
	sealed := gcm.Seal(nil, nonce, plaintext, aad)

	// Split ciphertext and tag. Tag is the last GCMTagSize bytes.
	ct := sealed[:len(sealed)-GCMTagSize]
	tag := sealed[len(sealed)-GCMTagSize:]

	return &EncryptResult{
		Ciphertext: ct,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

// DecryptAESGCM decrypts ciphertext using AES-256-GCM.
// The tag must be provided separately (it is appended to ciphertext for GCM.Open).
func DecryptAESGCM(ciphertext, key, nonce, tag, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidKeyLength, len(key))
	}
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidNonceLength, len(nonce))
	}
	if len(tag) != GCMTagSize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidTagLength, len(tag))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// GCM.Open expects ciphertext with tag appended.
	sealed := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", util.ErrDecryptFailed, err)
	}

	return plaintext, nil
}
