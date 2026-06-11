package vaultpack

import "github.com/Skpow1234/Vaultpack/internal/vpackop"

// RewrapOptions re-wraps a KMS-protected DEK without decrypting the payload.
type RewrapOptions struct {
	InputPath  string
	InputBytes []byte
	OutputPath string

	KMSProvider string
	FromKeyID   string
	ToKeyID     string
}

// RewrapResult is returned on successful rewrap.
type RewrapResult struct {
	Manifest   *Manifest
	OutputPath string
}

// Rewrap changes the KMS key wrapping the DEK while leaving ciphertext untouched.
func Rewrap(opts RewrapOptions) (*RewrapResult, error) {
	res, err := vpackop.Rewrap(vpackop.RewrapParams{
		InputPath:   opts.InputPath,
		InputBytes:  opts.InputBytes,
		OutputPath:  opts.OutputPath,
		KMSProvider: opts.KMSProvider,
		FromKeyID:   opts.FromKeyID,
		ToKeyID:     opts.ToKeyID,
	})
	if err != nil {
		return nil, err
	}
	return &RewrapResult{Manifest: res.Manifest, OutputPath: res.OutputPath}, nil
}
