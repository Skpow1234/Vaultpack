package crypto

import (
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// ML-KEM PEM block types (CIRCL scheme names).
const (
	pemTypeMLKEM768Pub  = "ML-KEM-768 PUBLIC KEY"
	pemTypeMLKEM768Priv  = "ML-KEM-768 PRIVATE KEY"
	pemTypeMLKEM1024Pub  = "ML-KEM-1024 PUBLIC KEY"
	pemTypeMLKEM1024Priv = "ML-KEM-1024 PRIVATE KEY"
)

// MLKEMPublicKey holds an ML-KEM public key for use in hybrid encapsulation.
type MLKEMPublicKey struct {
	Scheme string
	Pub    []byte
}

// MLKEMPrivateKey holds an ML-KEM private key for decapsulation.
type MLKEMPrivateKey struct {
	Scheme string
	Priv   []byte
}

func getMLKEMScheme(schemeName string) (kem.Scheme, error) {
	var circlName string
	switch schemeName {
	case HybridMLKEM768:
		circlName = "ML-KEM-768"
	case HybridMLKEM1024:
		circlName = "ML-KEM-1024"
	default:
		return nil, fmt.Errorf("unsupported ML-KEM scheme %q", schemeName)
	}
	s := schemes.ByName(circlName)
	if s == nil {
		return nil, fmt.Errorf("CIRCL scheme %q not found", circlName)
	}
	return s, nil
}

func getMLKEMSchemeFromPEMType(pemType string) (kem.Scheme, string, error) {
	switch pemType {
	case pemTypeMLKEM768Pub, pemTypeMLKEM768Priv:
		s, err := getMLKEMScheme(HybridMLKEM768)
		return s, HybridMLKEM768, err
	case pemTypeMLKEM1024Pub, pemTypeMLKEM1024Priv:
		s, err := getMLKEMScheme(HybridMLKEM1024)
		return s, HybridMLKEM1024, err
	default:
		return nil, "", fmt.Errorf("unknown ML-KEM PEM type %q", pemType)
	}
}

// GenerateMLKEMKeys generates a key pair for the given ML-KEM scheme.
// Returns PEM-encoded private and public keys.
func GenerateMLKEMKeys(schemeName string) (privPEM, pubPEM []byte, err error) {
	s, err := getMLKEMScheme(schemeName)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := s.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-KEM key pair: %w", err)
	}
	pubBytes, err := pub.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ML-KEM public key: %w", err)
	}
	privBytes, err := priv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ML-KEM private key: %w", err)
	}
	var pubType, privType string
	switch schemeName {
	case HybridMLKEM768:
		pubType, privType = pemTypeMLKEM768Pub, pemTypeMLKEM768Priv
	case HybridMLKEM1024:
		pubType, privType = pemTypeMLKEM1024Pub, pemTypeMLKEM1024Priv
	default:
		return nil, nil, fmt.Errorf("unsupported ML-KEM scheme %q", schemeName)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: pubBytes})
	return privPEM, pubPEM, nil
}

// ParseMLKEMPublicKeyPEM decodes a PEM block into an MLKEMPublicKey.
// Returns nil, nil if the block is not an ML-KEM public key.
func ParseMLKEMPublicKeyPEM(block *pem.Block) (*MLKEMPublicKey, error) {
	if block == nil {
		return nil, nil
	}
	_, schemeName, err := getMLKEMSchemeFromPEMType(block.Type)
	if err != nil {
		return nil, nil
	}
	if block.Type != pemTypeMLKEM768Pub && block.Type != pemTypeMLKEM1024Pub {
		return nil, nil
	}
	return &MLKEMPublicKey{Scheme: schemeName, Pub: block.Bytes}, nil
}

// ParseMLKEMPrivateKeyPEM decodes a PEM block into an MLKEMPrivateKey.
func ParseMLKEMPrivateKeyPEM(block *pem.Block) (*MLKEMPrivateKey, error) {
	if block == nil {
		return nil, nil
	}
	_, schemeName, err := getMLKEMSchemeFromPEMType(block.Type)
	if err != nil {
		return nil, nil
	}
	if block.Type != pemTypeMLKEM768Priv && block.Type != pemTypeMLKEM1024Priv {
		return nil, nil
	}
	return &MLKEMPrivateKey{Scheme: schemeName, Priv: block.Bytes}, nil
}

// encapsulateMLKEM encapsulates a DEK for an ML-KEM recipient (single-recipient).
// EphemeralPublicKey is set to the KEM ciphertext; WrappedDEK is empty (DEK derived from shared secret).
func encapsulateMLKEM(recipientPub *MLKEMPublicKey) (*HybridResult, error) {
	s, err := getMLKEMScheme(recipientPub.Scheme)
	if err != nil {
		return nil, err
	}
	pk, err := s.UnmarshalBinaryPublicKey(recipientPub.Pub)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM public key: %w", err)
	}
	ct, ss, err := s.Encapsulate(pk)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulate: %w", err)
	}
	dek, err := hkdfDerive(ss, nil, []byte("vaultpack-ml-kem-dek"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM HKDF: %w", err)
	}
	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ct,
		Scheme:             recipientPub.Scheme,
	}, nil
}

// decapsulateMLKEM recovers the DEK using the recipient's private key and KEM ciphertext.
func decapsulateMLKEM(privKey *MLKEMPrivateKey, ciphertext []byte) ([]byte, error) {
	s, err := getMLKEMScheme(privKey.Scheme)
	if err != nil {
		return nil, err
	}
	sk, err := s.UnmarshalBinaryPrivateKey(privKey.Priv)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM private key: %w", err)
	}
	ss, err := s.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	return hkdfDerive(ss, nil, []byte("vaultpack-ml-kem-dek"), AES256KeySize)
}

// wrapDEKMLKEM wraps an existing DEK for an ML-KEM recipient (multi-recipient).
func wrapDEKMLKEM(recipientPub *MLKEMPublicKey, dek []byte) (*HybridResult, error) {
	s, err := getMLKEMScheme(recipientPub.Scheme)
	if err != nil {
		return nil, err
	}
	pk, err := s.UnmarshalBinaryPublicKey(recipientPub.Pub)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM public key: %w", err)
	}
	ct, ss, err := s.Encapsulate(pk)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulate: %w", err)
	}
	wrapKey, err := hkdfDerive(ss, nil, []byte("vaultpack-ml-kem-wrap"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM HKDF: %w", err)
	}
	wrapped, err := aesGCMWrap(wrapKey, dek)
	if err != nil {
		return nil, err
	}
	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ct,
		WrappedDEK:         wrapped,
		Scheme:             recipientPub.Scheme,
	}, nil
}

// unwrapDEKMLKEM recovers a wrapped DEK for multi-recipient ML-KEM.
func unwrapDEKMLKEM(privKey *MLKEMPrivateKey, ciphertext, wrappedDEK []byte) ([]byte, error) {
	s, err := getMLKEMScheme(privKey.Scheme)
	if err != nil {
		return nil, err
	}
	sk, err := s.UnmarshalBinaryPrivateKey(privKey.Priv)
	if err != nil {
		return nil, fmt.Errorf("parse ML-KEM private key: %w", err)
	}
	ss, err := s.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	wrapKey, err := hkdfDerive(ss, nil, []byte("vaultpack-ml-kem-wrap"), AES256KeySize)
	if err != nil {
		return nil, err
	}
	return aesGCMUnwrap(wrapKey, wrappedDEK)
}
