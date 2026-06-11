package vaultpack

import (
	"io"

	"github.com/Skpow1234/Vaultpack/internal/vpackop"
)

// DecryptOptions controls a single Decrypt call.
type DecryptOptions struct {
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

	// KMSUnwrap overrides the default KMS provider unwrap (used by serve cache).
	KMSUnwrap func(wrapped []byte, keyID string) ([]byte, error)
}

// DecryptResult is what Decrypt returns on success.
type DecryptResult struct {
	Manifest  *Manifest
	Plaintext []byte
}

// Decrypt reads a .vpack bundle and recovers the plaintext.
func Decrypt(opts DecryptOptions) (*DecryptResult, error) {
	res, err := vpackop.Decrypt(toVpackopDecrypt(opts))
	if err != nil {
		return nil, err
	}
	return &DecryptResult{Manifest: res.Manifest, Plaintext: res.Plaintext}, nil
}
