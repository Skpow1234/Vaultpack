package crypto

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign"
	signschemes "github.com/cloudflare/circl/sign/schemes"
)

// PEM block types for ML-DSA (CIRCL scheme names).
const (
	pemTypeMLDSA65Priv = "ML-DSA-65 PRIVATE KEY"
	pemTypeMLDSA65Pub  = "ML-DSA-65 PUBLIC KEY"
	pemTypeMLDSA87Priv = "ML-DSA-87 PRIVATE KEY"
	pemTypeMLDSA87Pub  = "ML-DSA-87 PUBLIC KEY"
)

// MLDSASigner wraps a CIRCL ML-DSA private key for use as crypto.Signer.
// Sign(rand, digest, opts) signs the digest (used when the caller hashes first).
// For message signing use the scheme's Sign(key, message, nil) via SignMessage.
type MLDSASigner struct {
	Scheme sign.Scheme
	Key    sign.PrivateKey
}

// Sign implements crypto.Signer. It signs the digest (or message) with ML-DSA.
func (m *MLDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return m.Scheme.Sign(m.Key, digest, nil), nil
}

// Public implements crypto.Signer.
func (m *MLDSASigner) Public() crypto.PublicKey {
	return m.Key.Public()
}

// MLDSAPublicKey holds an ML-DSA public key for verification.
type MLDSAPublicKey struct {
	Scheme sign.Scheme
	Pub    []byte
}

func getMLDSAScheme(algo string) (sign.Scheme, error) {
	var name string
	switch algo {
	case SignAlgoMLDSA65:
		name = "ML-DSA-65"
	case SignAlgoMLDSA87:
		name = "ML-DSA-87"
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm %q", algo)
	}
	s := signschemes.ByName(name)
	if s == nil {
		return nil, fmt.Errorf("CIRCL sign scheme %q not found", name)
	}
	return s, nil
}

// GenerateMLDSAKeys generates a key pair for the given ML-DSA algorithm.
func GenerateMLDSAKeys(algo string) (privPEM, pubPEM []byte, err error) {
	s, err := getMLDSAScheme(algo)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := s.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA key: %w", err)
	}
	pubBytes, err := pub.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ML-DSA public key: %w", err)
	}
	privBytes, err := priv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ML-DSA private key: %w", err)
	}
	var pubType, privType string
	switch algo {
	case SignAlgoMLDSA65:
		pubType, privType = pemTypeMLDSA65Pub, pemTypeMLDSA65Priv
	case SignAlgoMLDSA87:
		pubType, privType = pemTypeMLDSA87Pub, pemTypeMLDSA87Priv
	default:
		return nil, nil, fmt.Errorf("unsupported ML-DSA algorithm %q", algo)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: pubBytes})
	return privPEM, pubPEM, nil
}

// ParseMLDSAPrivateKeyPEM decodes a PEM block into an MLDSASigner.
// Returns (nil, nil) if the block is not an ML-DSA private key.
func ParseMLDSAPrivateKeyPEM(block *pem.Block) (*MLDSASigner, error) {
	if block == nil {
		return nil, nil
	}
	var s sign.Scheme
	switch block.Type {
	case pemTypeMLDSA65Priv:
		s = signschemes.ByName("ML-DSA-65")
	case pemTypeMLDSA87Priv:
		s = signschemes.ByName("ML-DSA-87")
	default:
		return nil, nil
	}
	if s == nil {
		return nil, nil
	}
	priv, err := s.UnmarshalBinaryPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ML-DSA private key: %w", err)
	}
	return &MLDSASigner{Scheme: s, Key: priv}, nil
}

// ParseMLDSAPublicKeyPEM decodes a PEM block into an MLDSAPublicKey.
func ParseMLDSAPublicKeyPEM(block *pem.Block) (*MLDSAPublicKey, error) {
	if block == nil {
		return nil, nil
	}
	var s sign.Scheme
	switch block.Type {
	case pemTypeMLDSA65Pub:
		s = signschemes.ByName("ML-DSA-65")
	case pemTypeMLDSA87Pub:
		s = signschemes.ByName("ML-DSA-87")
	default:
		return nil, nil
	}
	if s == nil {
		return nil, nil
	}
	// Validate by unmarshaling
	if _, err := s.UnmarshalBinaryPublicKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse ML-DSA public key: %w", err)
	}
	return &MLDSAPublicKey{Scheme: s, Pub: block.Bytes}, nil
}

// VerifyMLDSA verifies an ML-DSA signature.
func VerifyMLDSA(pub *MLDSAPublicKey, message, signature []byte) bool {
	pk, err := pub.Scheme.UnmarshalBinaryPublicKey(pub.Pub)
	if err != nil {
		return false
	}
	return pub.Scheme.Verify(pk, message, signature, nil)
}
