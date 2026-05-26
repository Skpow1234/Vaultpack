package cli

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	vpcrypto "github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/transparency"
)

// rekorUploadOpts groups the inputs needed to upload a Rekor entry and attach
// the resulting TransparencyEntry to a manifest. The signing key half is only
// used so we can derive its PEM-encoded public key — the signature is supplied
// pre-computed.
type rekorUploadOpts struct {
	RekorURL  string
	PubKey    crypto.PublicKey
	Signature []byte
	// SignedData is the exact byte slice the signature covers. Rekor will
	// SHA-256 hash it server-side and compare against the entry's data.hash.
	SignedData []byte
	// CertChainPEM, when non-empty, replaces the bare public key in the Rekor
	// entry's `publicKey.content` field. It is also stored verbatim in the
	// TransparencyEntry. Used for keyless Fulcio flows.
	CertChainPEM string
	// Identity / OIDCIssuer are stored on the resulting TransparencyEntry for
	// audit / inspect rendering. Empty for non-keyless signatures.
	Identity   string
	OIDCIssuer string
}

// uploadToRekor performs the actual HTTP upload and returns a populated
// TransparencyEntry ready to append to the manifest.
func uploadToRekor(ctx context.Context, opts rekorUploadOpts) (bundle.TransparencyEntry, error) {
	// Resolve the PEM that goes into the Rekor entry: cert chain for keyless,
	// PKIX-encoded raw pubkey otherwise.
	var pubPEM []byte
	if opts.CertChainPEM != "" {
		pubPEM = []byte(opts.CertChainPEM)
	} else {
		p, err := vpcrypto.MarshalPublicKeyPEM(opts.PubKey)
		if err != nil {
			return bundle.TransparencyEntry{}, fmt.Errorf("marshal pubkey for rekor: %w", err)
		}
		pubPEM = p
	}

	client := transparency.NewRekorClient(opts.RekorURL)
	entry := transparency.BuildHashedRekord(pubPEM, opts.Signature, opts.SignedData)
	uuid, anon, err := client.Upload(ctx, entry)
	if err != nil {
		return bundle.TransparencyEntry{}, fmt.Errorf("rekor upload: %w", err)
	}
	if anon.Verification == nil || anon.Verification.SignedEntryTimestamp == "" {
		return bundle.TransparencyEntry{}, fmt.Errorf("rekor: no SET in response")
	}

	return bundle.TransparencyEntry{
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

// rekorSupportsAlgo returns true if Rekor can verify the given signing algo.
// Rekor uses Go stdlib's crypto/x509 to parse the public key, which means
// post-quantum signatures (ml-dsa, slh-dsa) and exotic curves (ed448) are not
// accepted. We reject those upfront with a clear error.
func rekorSupportsAlgo(algo string) bool {
	switch algo {
	case "ed25519",
		"ecdsa-p256", "ecdsa-p384",
		"rsa-pss-2048", "rsa-pss-4096":
		return true
	default:
		return false
	}
}

// sha256Hex is a tiny convenience for log / audit messages.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
