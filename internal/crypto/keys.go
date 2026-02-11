package crypto

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// AES256KeySize is the required key size for AES-256 in bytes.
	AES256KeySize = 32
	// KeyFilePrefix is the optional prefix for key files.
	KeyFilePrefix = "b64:"
)

// SaveKeyFile writes a symmetric key to a file as base64, prefixed with "b64:".
func SaveKeyFile(path string, key []byte) error {
	encoded := KeyFilePrefix + util.B64Encode(key) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("save key file: %w", err)
	}
	return nil
}

// LoadKeyFile reads a symmetric key from a base64-encoded key file.
// Accepts optional "b64:" prefix.
func LoadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load key file: %w", err)
	}

	content := strings.TrimSpace(string(data))
	content = strings.TrimPrefix(content, KeyFilePrefix)

	key, err := util.B64Decode(content)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", util.ErrInvalidKeyLength, len(key), AES256KeySize)
	}

	return key, nil
}

// KeyFingerprint computes a SHA-256 fingerprint of the raw key bytes.
func KeyFingerprint(key []byte) (algo string, digestB64 string) {
	h := sha256.Sum256(key)
	return "sha256", util.B64Encode(h[:])
}
