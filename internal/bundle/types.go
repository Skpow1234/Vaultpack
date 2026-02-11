package bundle

// ManifestVersion is the current manifest schema version.
const ManifestVersion = "v1"

// Manifest represents the manifest.json inside a .vpack bundle.
type Manifest struct {
	Version    string          `json:"version"`
	CreatedAt  string          `json:"created_at"`
	Input      InputMeta       `json:"input"`
	Plaintext  PlaintextHash   `json:"plaintext_hash"`
	Encryption EncryptionMeta  `json:"encryption"`
	Ciphertext CiphertextMeta  `json:"ciphertext"`
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
	AEAD     string  `json:"aead"`
	NonceB64 string  `json:"nonce_b64"`
	TagB64   string  `json:"tag_b64"`
	AADB64   *string `json:"aad_b64"`
	KeyID    KeyID   `json:"key_id"`
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
