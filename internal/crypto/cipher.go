package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Supported AEAD cipher names.
const (
	CipherAES256GCM           = "aes-256-gcm"
	CipherChaCha20Poly1305    = "chacha20-poly1305"
	CipherXChaCha20Poly1305   = "xchacha20-poly1305"
)

// AES256KeySize is the required key size for all supported ciphers (32 bytes).
const AES256KeySize = 32

// SupportedCiphers is the list of supported AEAD cipher names in presentation order.
var SupportedCiphers = []string{
	CipherAES256GCM,
	CipherChaCha20Poly1305,
	CipherXChaCha20Poly1305,
}

// CipherInfo describes the parameters of a supported AEAD cipher.
type CipherInfo struct {
	Name      string
	KeySize   int
	NonceSize int
	TagSize   int
}

// cipherRegistry maps cipher names to their info.
var cipherRegistry = map[string]CipherInfo{
	CipherAES256GCM: {
		Name:      CipherAES256GCM,
		KeySize:   32,
		NonceSize: 12,
		TagSize:   16,
	},
	CipherChaCha20Poly1305: {
		Name:      CipherChaCha20Poly1305,
		KeySize:   chacha20poly1305.KeySize,          // 32
		NonceSize: chacha20poly1305.NonceSize,         // 12
		TagSize:   16,                                 // Poly1305 tag
	},
	CipherXChaCha20Poly1305: {
		Name:      CipherXChaCha20Poly1305,
		KeySize:   chacha20poly1305.KeySize,           // 32
		NonceSize: chacha20poly1305.NonceSizeX,        // 24
		TagSize:   16,                                 // Poly1305 tag
	},
}

// SupportedCipher checks whether the given cipher name is supported.
func SupportedCipher(name string) bool {
	_, ok := cipherRegistry[name]
	return ok
}

// GetCipherInfo returns the CipherInfo for a supported cipher, or an error.
func GetCipherInfo(name string) (CipherInfo, error) {
	info, ok := cipherRegistry[name]
	if !ok {
		return CipherInfo{}, fmt.Errorf("unsupported cipher %q", name)
	}
	return info, nil
}

// NewAEAD creates a cipher.AEAD for the named cipher with the given key.
func NewAEAD(name string, key []byte) (cipher.AEAD, error) {
	info, ok := cipherRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher %q", name)
	}
	if len(key) != info.KeySize {
		return nil, fmt.Errorf("cipher %s: key must be %d bytes, got %d", name, info.KeySize, len(key))
	}

	switch name {
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
		return cipher.NewGCM(block)

	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)

	case CipherXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)

	default:
		return nil, fmt.Errorf("unsupported cipher %q", name)
	}
}
