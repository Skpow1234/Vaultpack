package vaultpack

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// Read parses a .vpack file from disk and returns its contents.
//
// The returned Bundle.Manifest is fully populated; ManifestBytes is the raw
// JSON exactly as stored, suitable for re-computing canonical signatures.
// Signature is nil if the bundle has no signature.sig entry.
func Read(path string) (*Bundle, error) {
	br, err := bundle.Read(path)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		Manifest:      br.Manifest,
		ManifestBytes: br.ManifestBytes,
		Ciphertext:    br.Ciphertext,
		Signature:     br.Signature,
	}, nil
}

// Inspect is a convenience wrapper around Read that only decodes the manifest
// and skips loading the (potentially large) ciphertext into memory.
func Inspect(path string) (*Manifest, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	m, _, err := bundle.ReadManifestOnly(path)
	if err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	return m, nil
}

// MarshalManifest serializes a manifest to indented JSON in the canonical
// VaultPack on-disk format. It is the inverse of bundle.UnmarshalManifest.
func MarshalManifest(m *Manifest) ([]byte, error) {
	return bundle.MarshalManifest(m)
}

// UnmarshalManifest parses manifest JSON bytes into a *Manifest.
func UnmarshalManifest(data []byte) (*Manifest, error) {
	return bundle.UnmarshalManifest(data)
}
