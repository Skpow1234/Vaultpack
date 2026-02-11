package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// GenerateSigningKeyPair creates a new Ed25519 private/public key pair.
func GenerateSigningKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return priv, pub, nil
}

// SaveSigningKey writes an Ed25519 private key to a file as base64.
func SaveSigningKey(path string, key ed25519.PrivateKey) error {
	encoded := "ed25519-priv:" + util.B64Encode(key) + "\n"
	return os.WriteFile(path, []byte(encoded), 0o600)
}

// SavePublicKey writes an Ed25519 public key to a file as base64.
func SavePublicKey(path string, key ed25519.PublicKey) error {
	encoded := "ed25519-pub:" + util.B64Encode(key) + "\n"
	return os.WriteFile(path, []byte(encoded), 0o644)
}

// LoadSigningKey reads an Ed25519 private key from a base64-encoded file.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}

	content := strings.TrimSpace(string(data))
	content = strings.TrimPrefix(content, "ed25519-priv:")

	raw, err := util.B64Decode(content)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}

	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: got %d, want %d", len(raw), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(raw), nil
}

// LoadPublicKey reads an Ed25519 public key from a base64-encoded file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}

	content := strings.TrimSpace(string(data))
	content = strings.TrimPrefix(content, "ed25519-pub:")

	raw, err := util.B64Decode(content)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(raw), nil
}

// Sign computes an Ed25519 signature over the given message.
func Sign(privKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privKey, message)
}

// Verify checks an Ed25519 signature over the given message.
func Verify(pubKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pubKey, message, sig)
}

// BuildSigningMessage constructs the message that gets signed:
// canonical manifest bytes concatenated with the SHA-256 of the payload.
func BuildSigningMessage(canonicalManifest, payloadHash []byte) []byte {
	msg := make([]byte, 0, len(canonicalManifest)+len(payloadHash))
	msg = append(msg, canonicalManifest...)
	msg = append(msg, payloadHash...)
	return msg
}
