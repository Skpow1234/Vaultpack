package bundle

import (
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// GCM constants.
	gcmNonceSize = 12 // bytes
	gcmTagSize   = 16 // bytes
	aes256KeyLen = 32 // bytes
)

// ValidateManifest checks that a parsed Manifest has valid, supported values.
func ValidateManifest(m *Manifest) error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("%w: got %q, want %q", util.ErrUnsupportedVersion, m.Version, ManifestVersion)
	}

	if m.Encryption.AEAD != "aes-256-gcm" {
		return fmt.Errorf("%w: aead %q", util.ErrUnsupportedAlgorithm, m.Encryption.AEAD)
	}

	nonceBytes, err := util.B64Decode(m.Encryption.NonceB64)
	if err != nil {
		return fmt.Errorf("%w: invalid nonce base64: %v", util.ErrManifestInvalid, err)
	}
	if len(nonceBytes) != gcmNonceSize {
		return fmt.Errorf("%w: nonce length %d, want %d", util.ErrInvalidNonceLength, len(nonceBytes), gcmNonceSize)
	}

	tagBytes, err := util.B64Decode(m.Encryption.TagB64)
	if err != nil {
		return fmt.Errorf("%w: invalid tag base64: %v", util.ErrManifestInvalid, err)
	}
	if len(tagBytes) != gcmTagSize {
		return fmt.Errorf("%w: tag length %d, want %d", util.ErrInvalidTagLength, len(tagBytes), gcmTagSize)
	}

	if !crypto.SupportedHashAlgo(m.Plaintext.Algo) {
		return fmt.Errorf("%w: plaintext hash algo %q", util.ErrUnsupportedAlgorithm, m.Plaintext.Algo)
	}

	if m.CreatedAt == "" {
		return fmt.Errorf("%w: created_at is empty", util.ErrManifestInvalid)
	}

	if m.Input.Name == "" {
		return fmt.Errorf("%w: input name is empty", util.ErrManifestInvalid)
	}

	// Validate chunk_size if present.
	if m.Encryption.ChunkSize != nil && *m.Encryption.ChunkSize <= 0 {
		return fmt.Errorf("%w: chunk_size must be positive, got %d", util.ErrManifestInvalid, *m.Encryption.ChunkSize)
	}

	return nil
}
