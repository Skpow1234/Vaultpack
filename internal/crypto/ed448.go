package crypto

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/ed448"
)

// PEM block types for Ed448 (RFC 8032).
const (
	pemTypeEd448Priv = "ED448 PRIVATE KEY"
	pemTypeEd448Pub  = "ED448 PUBLIC KEY"
)

// Ed448Signer wraps a CIRCL Ed448 private key for use as crypto.Signer.
type Ed448Signer struct {
	Key ed448.PrivateKey
}

// Sign implements crypto.Signer for Ed448 with empty context (RFC 8032 pure Ed448).
func (s *Ed448Signer) Sign(rnd io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ed448.Sign(s.Key, message, ""), nil
}

// Public implements crypto.Signer.
func (s *Ed448Signer) Public() crypto.PublicKey {
	return s.Key.Public()
}

// Ed448PublicKey holds an Ed448 public key for verification.
type Ed448PublicKey struct {
	Pub ed448.PublicKey
}

// GenerateEd448Keys generates a new Ed448 keypair, PEM-encoded.
func GenerateEd448Keys() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed448 key: %w", err)
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ed448 private key: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ed448 public key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypeEd448Priv, Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypeEd448Pub, Bytes: pubBytes})
	return privPEM, pubPEM, nil
}

// ParseEd448PrivateKeyPEM decodes a PEM block into an Ed448Signer.
// Returns (nil, nil) if the block is not an Ed448 private key.
func ParseEd448PrivateKeyPEM(block *pem.Block) (*Ed448Signer, error) {
	if block == nil || block.Type != pemTypeEd448Priv {
		return nil, nil
	}
	priv := ed448.PrivateKey(make([]byte, len(block.Bytes)))
	copy(priv, block.Bytes)
	return &Ed448Signer{Key: priv}, nil
}

// ParseEd448PublicKeyPEM decodes a PEM block into an Ed448PublicKey.
// Returns (nil, nil) if the block is not an Ed448 public key.
func ParseEd448PublicKeyPEM(block *pem.Block) (*Ed448PublicKey, error) {
	if block == nil || block.Type != pemTypeEd448Pub {
		return nil, nil
	}
	pub := ed448.PublicKey(make([]byte, len(block.Bytes)))
	copy(pub, block.Bytes)
	return &Ed448PublicKey{Pub: pub}, nil
}

// VerifyEd448 verifies an Ed448 signature with empty context.
func VerifyEd448(pub *Ed448PublicKey, message, signature []byte) bool {
	return ed448.Verify(pub.Pub, message, signature, "")
}
