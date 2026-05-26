package crypto

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign"
	signschemes "github.com/cloudflare/circl/sign/schemes"
)

// PEM block types for SLH-DSA (FIPS 205 / SPHINCS+).
const (
	pemTypeSLHDSA128sPriv = "SLH-DSA-128S PRIVATE KEY"
	pemTypeSLHDSA128sPub  = "SLH-DSA-128S PUBLIC KEY"
)

// circlSchemeNameFor maps our public algorithm name to the CIRCL scheme name.
func circlSchemeNameForSLHDSA(algo string) (string, error) {
	switch algo {
	case SignAlgoSLHDSA128s:
		// Use SHA2-128s (small) variant per FIPS 205 (most common, smallest signatures).
		return "SLH-DSA-SHA2-128s", nil
	default:
		return "", fmt.Errorf("unsupported SLH-DSA algorithm %q", algo)
	}
}

// SLHDSASigner wraps a CIRCL SLH-DSA private key for use as crypto.Signer.
// (Structurally identical to MLDSASigner but kept distinct for clarity and
// to allow distinct type-assertions in SignMessage/VerifySignature.)
type SLHDSASigner struct {
	Scheme sign.Scheme
	Key    sign.PrivateKey
}

// Sign implements crypto.Signer for SLH-DSA.
func (s *SLHDSASigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.Scheme.Sign(s.Key, message, nil), nil
}

// Public implements crypto.Signer.
func (s *SLHDSASigner) Public() crypto.PublicKey {
	return s.Key.Public()
}

// SLHDSAPublicKey holds an SLH-DSA public key for verification.
type SLHDSAPublicKey struct {
	Scheme sign.Scheme
	Pub    []byte
}

func getSLHDSAScheme(algo string) (sign.Scheme, error) {
	name, err := circlSchemeNameForSLHDSA(algo)
	if err != nil {
		return nil, err
	}
	s := signschemes.ByName(name)
	if s == nil {
		return nil, fmt.Errorf("CIRCL sign scheme %q not found", name)
	}
	return s, nil
}

// GenerateSLHDSAKeys generates a key pair for the given SLH-DSA algorithm.
func GenerateSLHDSAKeys(algo string) (privPEM, pubPEM []byte, err error) {
	s, err := getSLHDSAScheme(algo)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := s.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate SLH-DSA key: %w", err)
	}
	pubBytes, err := pub.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal SLH-DSA public key: %w", err)
	}
	privBytes, err := priv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal SLH-DSA private key: %w", err)
	}
	var pubType, privType string
	switch algo {
	case SignAlgoSLHDSA128s:
		pubType, privType = pemTypeSLHDSA128sPub, pemTypeSLHDSA128sPriv
	default:
		return nil, nil, fmt.Errorf("unsupported SLH-DSA algorithm %q", algo)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: pubBytes})
	return privPEM, pubPEM, nil
}

// ParseSLHDSAPrivateKeyPEM decodes a PEM block into an SLHDSASigner.
// Returns (nil, nil) if the block is not an SLH-DSA private key.
func ParseSLHDSAPrivateKeyPEM(block *pem.Block) (*SLHDSASigner, error) {
	if block == nil {
		return nil, nil
	}
	var s sign.Scheme
	switch block.Type {
	case pemTypeSLHDSA128sPriv:
		s = signschemes.ByName("SLH-DSA-SHA2-128s")
	default:
		return nil, nil
	}
	if s == nil {
		return nil, nil
	}
	priv, err := s.UnmarshalBinaryPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SLH-DSA private key: %w", err)
	}
	return &SLHDSASigner{Scheme: s, Key: priv}, nil
}

// ParseSLHDSAPublicKeyPEM decodes a PEM block into an SLHDSAPublicKey.
func ParseSLHDSAPublicKeyPEM(block *pem.Block) (*SLHDSAPublicKey, error) {
	if block == nil {
		return nil, nil
	}
	var s sign.Scheme
	switch block.Type {
	case pemTypeSLHDSA128sPub:
		s = signschemes.ByName("SLH-DSA-SHA2-128s")
	default:
		return nil, nil
	}
	if s == nil {
		return nil, nil
	}
	if _, err := s.UnmarshalBinaryPublicKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse SLH-DSA public key: %w", err)
	}
	return &SLHDSAPublicKey{Scheme: s, Pub: block.Bytes}, nil
}

// VerifySLHDSA verifies an SLH-DSA signature.
func VerifySLHDSA(pub *SLHDSAPublicKey, message, signature []byte) bool {
	pk, err := pub.Scheme.UnmarshalBinaryPublicKey(pub.Pub)
	if err != nil {
		return false
	}
	return pub.Scheme.Verify(pk, message, signature, nil)
}
