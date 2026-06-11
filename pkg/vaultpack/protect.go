package vaultpack

import (
	"io"

	"github.com/Skpow1234/Vaultpack/internal/vpackop"
)

// ProtectOptions controls a single Protect call.
//
// Exactly one of {Plaintext, PlaintextReader, InputPath} must be set.
// Exactly one of {OutputPath, OutputWriter} must be set.
//
// Key mode (pick at most one):
//   - Key or auto-generated key (default)
//   - Password (+ optional KDFAlgo)
//   - Recipients (hybrid / multi-recipient)
//   - KMSProvider + KMSKeyID
type ProtectOptions struct {
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

// SignParams configures Protect's optional signing step.
type SignParams struct {
	PrivateKey     []byte
	PrivateKeyPath string
	Algo           string
}

// ProtectResult is what Protect returns on success.
type ProtectResult struct {
	Manifest     *Manifest
	BundlePath   string
	BundleBytes  []byte
	GeneratedKey []byte
	Shares       []Share
	SignatureAlgo string
	Signature    []byte
}

// Protect encrypts the supplied plaintext and writes a .vpack bundle.
func Protect(opts ProtectOptions) (*ProtectResult, error) {
	res, err := vpackop.Protect(toVpackopProtect(opts))
	if err != nil {
		return nil, err
	}
	return fromVpackopProtect(res), nil
}
