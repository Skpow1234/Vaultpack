package vaultpack

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

// SignOptions controls a single Sign call.
//
// SignBundle rewrites an existing .vpack file in place, adding (or replacing)
// the detached signature.sig entry and populating manifest.signature_algo /
// manifest.signed_at. Exactly one of {PrivateKey, PrivateKeyPath} must be set.
type SignOptions struct {
	BundlePath     string
	PrivateKey     []byte
	PrivateKeyPath string
	Algo           string // optional override; otherwise auto-detected
}

// SignResult is what SignBundle returns on success.
type SignResult struct {
	Algorithm string
	SignedAt  string
	Signature []byte
}

// SignBundle re-writes the bundle at BundlePath with a fresh detached
// signature computed over the canonical manifest and the SHA-256 of the
// payload, using the supplied signing key.
func SignBundle(opts SignOptions) (*SignResult, error) {
	if opts.BundlePath == "" {
		return nil, errors.New("vaultpack.SignBundle: BundlePath is required")
	}
	if opts.PrivateKey == nil && opts.PrivateKeyPath == "" {
		return nil, errors.New("vaultpack.SignBundle: PrivateKey or PrivateKeyPath is required")
	}
	if opts.PrivateKey != nil && opts.PrivateKeyPath != "" {
		return nil, errors.New("vaultpack.SignBundle: PrivateKey and PrivateKeyPath are mutually exclusive")
	}

	br, err := bundle.Read(opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: read: %w", err)
	}

	var (
		signer   stdSigner
		detected string
	)
	if opts.PrivateKeyPath != "" {
		signer, detected, err = crypto.LoadPrivateKey(opts.PrivateKeyPath)
	} else {
		signer, detected, err = crypto.ParsePrivateKey(opts.PrivateKey)
	}
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: load key: %w", err)
	}

	algo := detected
	if opts.Algo != "" {
		if opts.Algo != detected {
			return nil, fmt.Errorf("vaultpack.SignBundle: Algo %q does not match key type %q", opts.Algo, detected)
		}
		algo = opts.Algo
	}

	br.Manifest.SignatureAlgo = &algo
	ts := time.Now().UTC().Format(time.RFC3339)
	br.Manifest.SignedAt = &ts

	canonical, err := bundle.CanonicalManifest(br.Manifest)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: canonicalize: %w", err)
	}
	payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: hash payload: %w", err)
	}
	sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
	sig, err := crypto.SignMessage(signer, algo, sigMsg)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: sign: %w", err)
	}

	manifestBytes, err := bundle.MarshalManifest(br.Manifest)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: marshal manifest: %w", err)
	}
	if err := bundle.Write(&bundle.WriteParams{
		OutputPath:    opts.BundlePath,
		Ciphertext:    br.Ciphertext,
		ManifestBytes: manifestBytes,
		Signature:     sig,
	}); err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: write: %w", err)
	}

	return &SignResult{
		Algorithm: algo,
		SignedAt:  ts,
		Signature: sig,
	}, nil
}
