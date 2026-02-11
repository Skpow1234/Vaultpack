package crypto

import (
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// GCMNonceSize is the standard nonce size for AES-GCM (kept for backward compat).
	GCMNonceSize = 12
	// GCMTagSize is the standard authentication tag size for AES-GCM / Poly1305.
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
// This is the legacy non-streaming path.
func EncryptAESGCM(plaintext, key, aad []byte) (*EncryptResult, error) {
	return EncryptAEAD(CipherAES256GCM, plaintext, key, aad)
}

// DecryptAESGCM decrypts ciphertext using AES-256-GCM.
// The tag must be provided separately.
// This is the legacy non-streaming path.
func DecryptAESGCM(ciphertext, key, nonce, tag, aad []byte) ([]byte, error) {
	return DecryptAEAD(CipherAES256GCM, ciphertext, key, nonce, tag, aad)
}

// EncryptAEAD encrypts plaintext with the named AEAD cipher.
// A random nonce is generated internally.
func EncryptAEAD(cipherName string, plaintext, key, aad []byte) (*EncryptResult, error) {
	aead, err := NewAEAD(cipherName, key)
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateNonce(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	// Seal appends the tag to the ciphertext.
	sealed := aead.Seal(nil, nonce, plaintext, aad)

	tagSize := aead.Overhead()
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return &EncryptResult{
		Ciphertext: ct,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

// DecryptAEAD decrypts ciphertext with the named AEAD cipher.
// The tag must be provided separately (it is appended to ciphertext for Open).
func DecryptAEAD(cipherName string, ciphertext, key, nonce, tag, aad []byte) ([]byte, error) {
	info, err := GetCipherInfo(cipherName)
	if err != nil {
		return nil, err
	}
	if len(key) != info.KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidKeyLength, len(key))
	}
	if len(nonce) != info.NonceSize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidNonceLength, len(nonce))
	}
	if len(tag) != info.TagSize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidTagLength, len(tag))
	}

	aead, err := NewAEAD(cipherName, key)
	if err != nil {
		return nil, err
	}

	// Open expects ciphertext with tag appended.
	sealed := append(ciphertext, tag...)

	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", util.ErrDecryptFailed, err)
	}

	return plaintext, nil
}
