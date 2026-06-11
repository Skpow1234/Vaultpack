// Package vpackop implements the core protect/decrypt pipeline shared by the
// public SDK, HTTP service, and CLI.
package vpackop

import (
	"io"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// Recipient identifies a hybrid-encryption recipient by PEM bytes or file path.
// Exactly one field must be set.
type Recipient struct {
	PublicKeyPEM  []byte
	PublicKeyPath string
}

// SignParams configures optional signing during Protect.
type SignParams struct {
	PrivateKey     []byte
	PrivateKeyPath string
	Algo           string
}

// ProtectParams controls bundle creation.
type ProtectParams struct {
	Plaintext       []byte
	PlaintextReader io.Reader
	InputPath       string
	InputName       string

	OutputPath   string
	OutputWriter io.Writer

	Key      []byte
	Password string
	KDFAlgo  string

	KMSProvider string
	KMSKeyID    string

	Recipients []Recipient

	Compress string // none, gzip, zstd

	SplitShares    int
	SplitThreshold int

	Cipher    string
	ChunkSize int
	HashAlgo  string
	AAD       []byte

	ParallelWorkers int

	Sign *SignParams
}

// Share is one Shamir share produced when SplitShares > 0.
type Share struct {
	Index int
	Data  []byte
}

// ProtectResult is returned by Protect on success.
type ProtectResult struct {
	Manifest      *bundle.Manifest
	BundlePath    string
	GeneratedKey  []byte
	Shares        []Share
	SignatureAlgo string
	Signature     []byte
}

// DecryptParams controls bundle decryption.
type DecryptParams struct {
	InputPath  string
	InputBytes []byte

	OutputPath   string
	OutputWriter io.Writer

	Key      []byte
	Password string

	PrivateKey     []byte
	PrivateKeyPath string

	KMSProvider string

	AAD []byte

	ParallelWorkers int

	// KMSUnwrap, when set, is called instead of kms.Get(provider).UnwrapDEK.
	// Used by serve to plug in the unwrap cache.
	KMSUnwrap func(wrapped []byte, keyID string) ([]byte, error)
}

// DecryptResult is returned by Decrypt on success.
type DecryptResult struct {
	Manifest  *bundle.Manifest
	Plaintext []byte
}
