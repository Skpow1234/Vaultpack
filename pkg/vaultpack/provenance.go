package vaultpack

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	vpcrypto "github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/transparency"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// Provenance is a SLSA-style provenance statement for a bundle.
type Provenance = audit.Provenance

// BuildProvenance creates a provenance statement for a bundle.
func BuildProvenance(bundlePath, bundleDigestHex, inputName string, inputSize int64, plaintextHashAlgo, plaintextHashB64 string) *Provenance {
	return audit.BuildProvenance(bundlePath, bundleDigestHex, inputName, inputSize, plaintextHashAlgo, plaintextHashB64)
}

// MarshalProvenance returns indented JSON for a provenance statement.
func MarshalProvenance(p *Provenance) ([]byte, error) {
	return audit.MarshalProvenance(p)
}

// AddProvenance embeds provenance.json into an existing bundle on disk.
func AddProvenance(bundlePath string, provenanceJSON []byte) error {
	return bundle.AddProvenanceToBundle(bundlePath, provenanceJSON)
}

// TransparencyUploadOptions configures Rekor upload after signing.
type TransparencyUploadOptions struct {
	RekorURL     string
	PublicKey    crypto.PublicKey
	Signature    []byte
	SignedData   []byte
	CertChainPEM string
	Identity     string
	OIDCIssuer   string
}

// UploadTransparency uploads a signature to Rekor and returns a manifest entry.
func UploadTransparency(ctx context.Context, opts TransparencyUploadOptions) (TransparencyEntry, error) {
	if opts.RekorURL == "" {
		opts.RekorURL = transparency.DefaultRekorURL
	}
	var pubPEM []byte
	if opts.CertChainPEM != "" {
		pubPEM = []byte(opts.CertChainPEM)
	} else if opts.PublicKey != nil {
		p, err := vpcrypto.MarshalPublicKeyPEM(opts.PublicKey)
		if err != nil {
			return TransparencyEntry{}, fmt.Errorf("marshal pubkey: %w", err)
		}
		pubPEM = p
	} else {
		return TransparencyEntry{}, fmt.Errorf("PublicKey or CertChainPEM is required")
	}
	client := transparency.NewRekorClient(opts.RekorURL)
	entry := transparency.BuildHashedRekord(pubPEM, opts.Signature, opts.SignedData)
	uuid, anon, err := client.Upload(ctx, entry)
	if err != nil {
		return TransparencyEntry{}, fmt.Errorf("rekor upload: %w", err)
	}
	if anon.Verification == nil || anon.Verification.SignedEntryTimestamp == "" {
		return TransparencyEntry{}, fmt.Errorf("rekor: no SET in response")
	}
	return TransparencyEntry{
		LogURL:         client.BaseURL,
		LogID:          anon.LogID,
		LogIndex:       anon.LogIndex,
		UUID:           uuid,
		IntegratedTime: anon.IntegratedTime,
		SETB64:         anon.Verification.SignedEntryTimestamp,
		EntryB64:       anon.Body,
		Format:         transparency.KindHashedRekord,
		CertChainPEM:   opts.CertChainPEM,
		Identity:       opts.Identity,
		OIDCIssuer:     opts.OIDCIssuer,
	}, nil
}

// RekorSupportsAlgo reports whether Rekor accepts signatures from this algorithm.
func RekorSupportsAlgo(algo string) bool {
	switch algo {
	case "ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-pss-2048", "rsa-pss-4096":
		return true
	default:
		return false
	}
}

// VerifyTransparencyOptions configures transparency proof verification.
type VerifyTransparencyOptions struct {
	Entry           TransparencyEntry
	SigningMessage  []byte
	BundleSignature []byte
	RekorPublicKeyPEM []byte
	RekorPublicKeyPath string
}

// VerifyTransparency validates a manifest transparency entry against bundle signature material.
func VerifyTransparency(opts VerifyTransparencyOptions) error {
	entry := opts.Entry
	if entry.EntryB64 == "" {
		return fmt.Errorf("transparency entry has no body")
	}
	var rec transparency.HashedRekordEntry
	if err := transparency.DecodeBody(entry.EntryB64, &rec); err != nil {
		return fmt.Errorf("decode rekor body: %w", err)
	}
	wantHash := sha256.Sum256(opts.SigningMessage)
	if rec.Spec.Data.Hash.Algorithm != "sha256" {
		return fmt.Errorf("unsupported rekor hash algorithm %q", rec.Spec.Data.Hash.Algorithm)
	}
	if rec.Spec.Data.Hash.Value != hex.EncodeToString(wantHash[:]) {
		return fmt.Errorf("rekor data hash does not match bundle signing message")
	}
	if rec.Spec.Signature.Content != util.B64Encode(opts.BundleSignature) {
		return fmt.Errorf("rekor signature content does not match bundle signature")
	}
	var pubPEM []byte
	switch {
	case len(opts.RekorPublicKeyPEM) > 0:
		pubPEM = opts.RekorPublicKeyPEM
	case opts.RekorPublicKeyPath != "":
		b, err := os.ReadFile(opts.RekorPublicKeyPath)
		if err != nil {
			return fmt.Errorf("read rekor pubkey: %w", err)
		}
		pubPEM = b
	default:
		client := transparency.NewRekorClient(entry.LogURL)
		var err error
		pubPEM, err = client.PublicKey(context.Background())
		if err != nil {
			return fmt.Errorf("fetch rekor pubkey: %w", err)
		}
	}
	return transparency.VerifySET(transparency.VerifyParams{
		RekorPubPEM:    pubPEM,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
		IntegratedTime: entry.IntegratedTime,
		Body:           entry.EntryB64,
		SETB64:         entry.SETB64,
	})
}
