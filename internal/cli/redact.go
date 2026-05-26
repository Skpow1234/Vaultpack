package cli

import (
	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// RedactedManifest is a safe, fingerprint-free view of a bundle manifest.
// It is intended for sharing inspect output without leaking values that
// could enable correlation (plaintext-hash fingerprinting), key identification,
// or per-encryption material that may aid cryptanalysis.
type RedactedManifest struct {
	Version       string                  `json:"version"`
	CreatedAt     string                  `json:"created_at,omitempty"`
	Input         bundle.InputMeta        `json:"input"`
	Plaintext     RedactedPlaintext       `json:"plaintext_hash"`
	Encryption    RedactedEncryption      `json:"encryption"`
	Compression   *RedactedCompression    `json:"compression,omitempty"`
	KeySplitting  *bundle.KeySplitMeta    `json:"key_splitting,omitempty"`
	SignatureAlgo *string                 `json:"signature_algo,omitempty"`
	Signed        bool                    `json:"signed"`
	Ciphertext    bundle.CiphertextMeta   `json:"ciphertext"`
}

// RedactedPlaintext omits the digest itself (keeps only the algorithm).
type RedactedPlaintext struct {
	Algo string `json:"algo"`
}

// RedactedEncryption omits nonce/tag/AAD/key id/wrapped DEK and other per-encryption values.
type RedactedEncryption struct {
	AEAD       string          `json:"aead"`
	Chunked    bool            `json:"chunked"`
	ChunkSize  *int            `json:"chunk_size,omitempty"`
	KDF        *RedactedKDF    `json:"kdf,omitempty"`
	Hybrid     *RedactedHybrid `json:"hybrid,omitempty"`
	HasKMS     bool            `json:"has_kms"`
}

// RedactedKDF omits the salt and other per-derivation parameters that might be sensitive.
type RedactedKDF struct {
	Algo string `json:"algo"`
}

// RedactedHybrid keeps only the scheme name and recipient count.
type RedactedHybrid struct {
	Scheme     string `json:"scheme"`
	Recipients int    `json:"recipients"`
}

// RedactedCompression mirrors CompressionMeta but only exposes the algorithm name.
type RedactedCompression struct {
	Algo string `json:"algo"`
}

// Redact builds a RedactedManifest from a full Manifest.
func Redact(m *bundle.Manifest) *RedactedManifest {
	r := &RedactedManifest{
		Version:    m.Version,
		Input:      m.Input,
		Plaintext:  RedactedPlaintext{Algo: m.Plaintext.Algo},
		Encryption: RedactedEncryption{
			AEAD:      m.Encryption.AEAD,
			Chunked:   m.Encryption.IsChunked(),
			ChunkSize: m.Encryption.ChunkSize,
			HasKMS:    m.Encryption.KmsKeyID != "" || m.Encryption.KmsWrappedDEKB64 != "",
		},
		KeySplitting:  m.KeySplitting,
		SignatureAlgo: m.SignatureAlgo,
		Signed:        m.SignatureAlgo != nil,
		Ciphertext:    m.Ciphertext,
	}
	if m.Encryption.KDF != nil {
		r.Encryption.KDF = &RedactedKDF{Algo: m.Encryption.KDF.Algo}
	}
	if m.Encryption.Hybrid != nil {
		r.Encryption.Hybrid = &RedactedHybrid{
			Scheme:     m.Encryption.Hybrid.Scheme,
			Recipients: len(m.Encryption.Hybrid.Recipients),
		}
		// Treat the single-recipient case as 1 recipient.
		if r.Encryption.Hybrid.Recipients == 0 {
			r.Encryption.Hybrid.Recipients = 1
		}
	}
	if m.Compress != nil {
		r.Compression = &RedactedCompression{Algo: m.Compress.Algo}
	}
	return r
}
