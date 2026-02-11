package bundle

// ManifestVersion is the current manifest schema version.
const ManifestVersion = "v1"

// Manifest represents the manifest.json inside a .vpack bundle.
type Manifest struct {
	Version       string         `json:"version"`
	CreatedAt     string         `json:"created_at"`
	Input         InputMeta      `json:"input"`
	Plaintext     PlaintextHash  `json:"plaintext_hash"`
	Encryption    EncryptionMeta `json:"encryption"`
	Ciphertext    CiphertextMeta `json:"ciphertext"`
	SignatureAlgo *string        `json:"signature_algo,omitempty"` // nil = unsigned or legacy ed25519
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
	AEAD      string      `json:"aead"`
	NonceB64  string      `json:"nonce_b64"`
	TagB64    string      `json:"tag_b64"`
	AADB64    *string     `json:"aad_b64"`
	KeyID     KeyID       `json:"key_id"`
	ChunkSize *int        `json:"chunk_size,omitempty"` // nil for non-chunked (backward compat)
	KDF       *KDFMeta    `json:"kdf,omitempty"`        // nil for key-file encryption
	Hybrid    *HybridMeta `json:"hybrid,omitempty"`     // nil for symmetric-only encryption
}

// HybridMeta describes the hybrid/asymmetric key encapsulation parameters.
type HybridMeta struct {
	Scheme                string `json:"scheme"`                            // e.g. "x25519-aes-256-gcm"
	EphemeralPubKeyB64    string `json:"ephemeral_public_key_b64,omitempty"` // for ECDH schemes
	WrappedDEKB64         string `json:"wrapped_dek_b64,omitempty"`          // for RSA-OAEP schemes
	RecipientFingerprintB64 string `json:"recipient_fingerprint_b64"`        // SHA-256 of recipient's public key
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
