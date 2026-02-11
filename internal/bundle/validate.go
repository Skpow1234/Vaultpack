package bundle

import (
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// ValidateManifest checks that a parsed Manifest has valid, supported values.
func ValidateManifest(m *Manifest) error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("%w: got %q, want %q", util.ErrUnsupportedVersion, m.Version, ManifestVersion)
	}

	// Validate AEAD cipher.
	cipherInfo, err := crypto.GetCipherInfo(m.Encryption.AEAD)
	if err != nil {
		return fmt.Errorf("%w: aead %q", util.ErrUnsupportedAlgorithm, m.Encryption.AEAD)
	}

	// Validate nonce.
	nonceBytes, err := util.B64Decode(m.Encryption.NonceB64)
	if err != nil {
		return fmt.Errorf("%w: invalid nonce base64: %v", util.ErrManifestInvalid, err)
	}
	if len(nonceBytes) != cipherInfo.NonceSize {
		return fmt.Errorf("%w: nonce length %d, want %d for %s",
			util.ErrInvalidNonceLength, len(nonceBytes), cipherInfo.NonceSize, cipherInfo.Name)
	}

	// Validate tag.
	tagBytes, err := util.B64Decode(m.Encryption.TagB64)
	if err != nil {
		return fmt.Errorf("%w: invalid tag base64: %v", util.ErrManifestInvalid, err)
	}
	if len(tagBytes) != cipherInfo.TagSize {
		return fmt.Errorf("%w: tag length %d, want %d for %s",
			util.ErrInvalidTagLength, len(tagBytes), cipherInfo.TagSize, cipherInfo.Name)
	}

	// Validate hash algorithm.
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

	// Validate KDF parameters if present.
	if m.Encryption.KDF != nil {
		kdf := m.Encryption.KDF
		if !crypto.SupportedKDF(kdf.Algo) {
			return fmt.Errorf("%w: kdf algo %q", util.ErrUnsupportedAlgorithm, kdf.Algo)
		}
		if kdf.SaltB64 == "" {
			return fmt.Errorf("%w: kdf salt is empty", util.ErrManifestInvalid)
		}
		saltBytes, err := util.B64Decode(kdf.SaltB64)
		if err != nil {
			return fmt.Errorf("%w: invalid kdf salt base64: %v", util.ErrManifestInvalid, err)
		}
		if len(saltBytes) < 8 {
			return fmt.Errorf("%w: kdf salt too short (%d bytes, want >= 8)", util.ErrManifestInvalid, len(saltBytes))
		}
	}

	return nil
}
