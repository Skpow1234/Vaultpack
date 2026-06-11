package vaultpack

import (
	stdcrypto "crypto"
)

type stdSigner = stdcrypto.Signer
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

// SignBytes is the in-memory counterpart of SignBundle. It accepts the raw
// bundle bytes, returns the re-signed bundle bytes along with the signature
// metadata. Browser / WASM friendly.
func SignBytes(bundleBytes []byte, opts SignOptions) ([]byte, *SignResult, error) {
	if opts.PrivateKey == nil && opts.PrivateKeyPath == "" {
		return nil, nil, errors.New("vaultpack.SignBytes: PrivateKey or PrivateKeyPath is required")
	}
	br, err := bundle.ReadBytes(bundleBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: read: %w", err)
	}
	signer, detected, err := loadSigner(opts.PrivateKey, opts.PrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	algo := detected
	if opts.Algo != "" {
		if opts.Algo != detected {
			return nil, nil, fmt.Errorf("vaultpack.SignBytes: Algo %q does not match key type %q", opts.Algo, detected)
		}
		algo = opts.Algo
	}
	br.Manifest.SignatureAlgo = &algo
	ts := time.Now().UTC().Format(time.RFC3339)
	br.Manifest.SignedAt = &ts

	canonical, err := bundle.CanonicalManifest(br.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: canonicalize: %w", err)
	}
	payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
	if err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: hash: %w", err)
	}
	sig, err := crypto.SignMessage(signer, algo, crypto.BuildSigningMessage(canonical, payloadHash))
	if err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: sign: %w", err)
	}
	mb, err := bundle.MarshalManifest(br.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: marshal manifest: %w", err)
	}
	var out bytes.Buffer
	if err := bundle.Write(&bundle.WriteParams{
		Writer:        &out,
		Ciphertext:    br.Ciphertext,
		ManifestBytes: mb,
		Signature:     sig,
	}); err != nil {
		return nil, nil, fmt.Errorf("vaultpack.SignBytes: write: %w", err)
	}
	return out.Bytes(), &SignResult{Algorithm: algo, SignedAt: ts, Signature: sig}, nil
}

func loadSigner(pk []byte, pkPath string) (stdSigner, string, error) {
	if pk != nil && pkPath != "" {
		return nil, "", errors.New("PrivateKey and PrivateKeyPath are mutually exclusive")
	}
	if pkPath != "" {
		return crypto.LoadPrivateKey(pkPath)
	}
	return crypto.ParsePrivateKey(pk)
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

	br, err := bundle.Read(opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.SignBundle: read: %w", err)
	}
	signer, detected, err := loadSigner(opts.PrivateKey, opts.PrivateKeyPath)
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
