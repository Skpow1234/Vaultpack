package bundle

// Manifest schema versions.
const (
	ManifestVersionV1 = "v1"
	ManifestVersionV2 = "v2"
)

// ManifestVersion is the current (latest) manifest schema version.
const ManifestVersion = ManifestVersionV2

// SupportedManifestVersions lists all versions the reader can handle.
var SupportedManifestVersions = []string{ManifestVersionV1, ManifestVersionV2}

// IsSupportedManifestVersion returns true if the version string is known.
func IsSupportedManifestVersion(v string) bool {
	for _, sv := range SupportedManifestVersions {
		if sv == v {
			return true
		}
	}
	return false
}

// Manifest represents the manifest.json inside a .vpack bundle.
type Manifest struct {
	Version       string          `json:"version"`
	CreatedAt     string          `json:"created_at"`
	Input         InputMeta       `json:"input"`
	Plaintext     PlaintextHash   `json:"plaintext_hash"`
	Encryption    EncryptionMeta  `json:"encryption"`
	Ciphertext    CiphertextMeta  `json:"ciphertext"`
	SignatureAlgo *string          `json:"signature_algo,omitempty"` // nil = unsigned or legacy ed25519
	SignedAt      *string          `json:"signed_at,omitempty"`      // RFC 3339 timestamp of signature
	Compress      *CompressionMeta `json:"compression,omitempty"`    // nil = no compression
	KeySplitting  *KeySplitMeta   `json:"key_splitting,omitempty"`  // nil = key not split
}

// InputMeta describes the original plaintext file.
type InputMeta struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// PlaintextHash holds the hash of the original plaintext.
type PlaintextHash struct {
	Algo      string `json:"algo"`
	DigestB64 string `json:"digest_b64"`
}

// EncryptionMeta describes the AEAD encryption parameters.
type EncryptionMeta struct {
	AEAD             string      `json:"aead"`
	NonceB64         string      `json:"nonce_b64"`
	TagB64           string      `json:"tag_b64"`
	AADB64           *string     `json:"aad_b64"`
	KeyID            KeyID       `json:"key_id"`
	ChunkSize        *int        `json:"chunk_size,omitempty"` // nil for non-chunked (backward compat)
	KDF              *KDFMeta    `json:"kdf,omitempty"`        // nil for key-file encryption
	Hybrid           *HybridMeta `json:"hybrid,omitempty"`     // nil for symmetric-only encryption
	KmsKeyID         string      `json:"kms_key_id,omitempty"`         // KMS key identifier when DEK is KMS-wrapped
	KmsWrappedDEKB64 string      `json:"kms_wrapped_dek_b64,omitempty"` // base64-encoded KMS-wrapped DEK
}

// HybridMeta describes the hybrid/asymmetric key encapsulation parameters.
type HybridMeta struct {
	Scheme                  string           `json:"scheme"`                             // e.g. "x25519-aes-256-gcm"
	EphemeralPubKeyB64      string           `json:"ephemeral_public_key_b64,omitempty"` // for ECDH schemes (single-recipient)
	WrappedDEKB64           string           `json:"wrapped_dek_b64,omitempty"`          // for RSA-OAEP schemes (single-recipient)
	RecipientFingerprintB64 string           `json:"recipient_fingerprint_b64,omitempty"` // SHA-256 of recipient pub key (single)
	Recipients              []RecipientEntry `json:"recipients,omitempty"`               // multi-recipient wrapped DEKs
}

// RecipientEntry stores per-recipient key encapsulation data for multi-recipient bundles.
type RecipientEntry struct {
	Scheme             string `json:"scheme"`
	FingerprintB64     string `json:"fingerprint_b64"`
	EphemeralPubKeyB64 string `json:"ephemeral_public_key_b64,omitempty"`
	WrappedDEKB64      string `json:"wrapped_dek_b64,omitempty"`
}

// CompressionMeta describes optional pre-encryption compression.
type CompressionMeta struct {
	Algo         string `json:"algo"`          // "gzip", "zstd"
	OriginalSize int64  `json:"original_size"` // size before compression
}

// KDFMeta describes the key derivation function parameters for password-based encryption.
type KDFMeta struct {
	Algo    string `json:"algo"`
	SaltB64 string `json:"salt_b64"`

	// Argon2id parameters.
	Time    uint32 `json:"time,omitempty"`
	Memory  uint32 `json:"memory,omitempty"`  // KiB
	Threads uint8  `json:"threads,omitempty"`

	// scrypt parameters.
	N int `json:"n,omitempty"`
	R int `json:"r,omitempty"`
	P int `json:"p,omitempty"`

	// PBKDF2 parameters.
	Iterations int `json:"iterations,omitempty"`
}

// KeySplitMeta records that the encryption key was split using Shamir's Secret Sharing.
type KeySplitMeta struct {
	Scheme    string `json:"scheme"`    // "shamir-gf256"
	Threshold int    `json:"threshold"` // K: minimum shares needed
	Total     int    `json:"total"`     // N: total shares created
}

// IsChunked returns true if the encryption uses chunked streaming mode.
func (e *EncryptionMeta) IsChunked() bool {
	return e.ChunkSize != nil && *e.ChunkSize > 0
}

// KeyID is a fingerprint of the encryption key for early mismatch detection.
type KeyID struct {
	Algo      string `json:"algo"`
	DigestB64 string `json:"digest_b64"`
}

// CiphertextMeta describes the encrypted payload.
type CiphertextMeta struct {
	Size int64 `json:"size"`
}
