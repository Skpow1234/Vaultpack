package vpackop

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// RewrapParams re-wraps a KMS-protected DEK without decrypting the payload.
type RewrapParams struct {
	InputPath  string
	InputBytes []byte
	OutputPath string

	KMSProvider string
	FromKeyID   string
	ToKeyID     string
}

// RewrapResult is returned on successful rewrap.
type RewrapResult struct {
	Manifest   *bundle.Manifest
	OutputPath string
}

// Rewrap changes the KMS key wrapping the DEK while leaving ciphertext untouched.
func Rewrap(p RewrapParams) (*RewrapResult, error) {
	if p.KMSProvider == "" {
		return nil, fmt.Errorf("vpackop.Rewrap: KMSProvider is required")
	}
	if p.ToKeyID == "" {
		return nil, fmt.Errorf("vpackop.Rewrap: ToKeyID is required")
	}
	br, err := readBundle(DecryptParams{InputPath: p.InputPath, InputBytes: p.InputBytes})
	if err != nil {
		return nil, err
	}
	if br.Manifest.Encryption.KmsKeyID == "" || br.Manifest.Encryption.KmsWrappedDEKB64 == "" {
		return nil, fmt.Errorf("bundle is not KMS-wrapped")
	}
	if p.FromKeyID != "" && p.FromKeyID != br.Manifest.Encryption.KmsKeyID {
		return nil, fmt.Errorf("FromKeyID %q does not match manifest %q", p.FromKeyID, br.Manifest.Encryption.KmsKeyID)
	}
	provider := kms.Get(p.KMSProvider)
	if provider == nil {
		return nil, fmt.Errorf("KMS provider %q not found; available: %v", p.KMSProvider, kms.Providers())
	}
	wrapped, err := util.B64Decode(br.Manifest.Encryption.KmsWrappedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped DEK: %w", err)
	}
	dek, err := provider.UnwrapDEK(wrapped, br.Manifest.Encryption.KmsKeyID)
	if err != nil {
		return nil, fmt.Errorf("KMS unwrap: %w", err)
	}
	newWrapped, err := provider.WrapDEK(dek, p.ToKeyID)
	if err != nil {
		return nil, fmt.Errorf("KMS wrap: %w", err)
	}
	oldKeyID := br.Manifest.Encryption.KmsKeyID
	br.Manifest.Encryption.KmsKeyID = p.ToKeyID
	br.Manifest.Encryption.KmsWrappedDEKB64 = util.B64Encode(newWrapped)

	prevHash := ""
	if p.InputPath != "" {
		if data, err := os.ReadFile(p.InputPath); err == nil {
			sum := sha256.Sum256(data)
			prevHash = hex.EncodeToString(sum[:])
		}
	}
	appendRotation(br.Manifest, prevHash, audit.OpRewrap,
		fmt.Sprintf("kms %s: %s -> %s", p.KMSProvider, oldKeyID, p.ToKeyID))

	manifestBytes, err := bundle.MarshalManifest(br.Manifest)
	if err != nil {
		return nil, err
	}
	outPath := p.OutputPath
	if outPath == "" {
		outPath = p.InputPath
	}
	if err := bundle.Write(&bundle.WriteParams{
		OutputPath:    outPath,
		Ciphertext:    br.Ciphertext,
		ManifestBytes: manifestBytes,
	}); err != nil {
		return nil, fmt.Errorf("write bundle: %w", err)
	}
	return &RewrapResult{Manifest: br.Manifest, OutputPath: outPath}, nil
}

func appendRotation(m *bundle.Manifest, prevBundleHash, operation, notes string) {
	m.SignatureAlgo = nil
	m.SignedAt = nil
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	m.RotatedFrom = append(m.RotatedFrom, bundle.RotationEntry{
		Operation:  operation,
		RotatedAt:  m.CreatedAt,
		BundleHash: prevBundleHash,
		Notes:      notes,
	})
}
