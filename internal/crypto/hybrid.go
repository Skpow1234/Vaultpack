package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/hkdf"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// Hybrid encryption scheme names.
const (
	HybridX25519AES256GCM = "x25519-aes-256-gcm"
	HybridECIESP256       = "ecies-p256"
	HybridRSAOAEP2048     = "rsa-oaep-2048"
	HybridRSAOAEP4096     = "rsa-oaep-4096"
	HybridMLKEM768        = "ml-kem-768"
	HybridMLKEM1024       = "ml-kem-1024"
)

// SupportedHybridSchemes is the list of supported hybrid/asymmetric encryption scheme names.
var SupportedHybridSchemes = []string{
	HybridX25519AES256GCM,
	HybridECIESP256,
	HybridRSAOAEP2048,
	HybridRSAOAEP4096,
	HybridMLKEM768,
	HybridMLKEM1024,
}

// SupportedHybridScheme checks whether the given scheme name is supported.
func SupportedHybridScheme(name string) bool {
	for _, s := range SupportedHybridSchemes {
		if s == name {
			return true
		}
	}
	return false
}

// HybridResult holds the output of a hybrid encryption key encapsulation.
type HybridResult struct {
	DEK                []byte // Data Encryption Key (32 bytes)
	EphemeralPublicKey []byte // Ephemeral public key bytes (for ECDH schemes)
	WrappedDEK         []byte // Wrapped DEK (for RSA-OAEP schemes)
	Scheme             string // Scheme name
}

// HybridEncapsulate generates a random DEK and encapsulates it for the recipient.
// recipientPubKeyPath is the path to the recipient's PEM-encoded public key.
func HybridEncapsulate(scheme string, recipientPubKeyPath string) (*HybridResult, error) {
	pubKeyBytes, err := os.ReadFile(recipientPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read recipient public key: %w", err)
	}

	pubKey, err := parsePublicKeyPEM(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	switch scheme {
	case HybridX25519AES256GCM:
		return encapsulateX25519(pubKey)
	case HybridECIESP256:
		return encapsulateECIESP256(pubKey)
	case HybridRSAOAEP2048, HybridRSAOAEP4096:
		return encapsulateRSAOAEP(pubKey, scheme)
	case HybridMLKEM768, HybridMLKEM1024:
		pq, ok := pubKey.(*MLKEMPublicKey)
		if !ok {
			return nil, fmt.Errorf("ml-kem: expected MLKEMPublicKey, got %T", pubKey)
		}
		return encapsulateMLKEM(pq)
	default:
		return nil, fmt.Errorf("unsupported hybrid scheme %q", scheme)
	}
}

// HybridEncapsulateWithDEK wraps an existing DEK for a recipient (used for multi-recipient).
// For ECDH schemes the DEK is re-derived (a new ephemeral is generated), so the returned
// HybridResult.DEK equals the original dek only for RSA-OAEP.  For ECDH schemes, the caller
// must use RSA-OAEP wrapping for multi-recipient or accept per-recipient DEKs.
//
// In practice: for multi-recipient we generate one random DEK and wrap it with RSA-OAEP, or
// for ECDH schemes we encrypt the DEK with an additional AEAD layer (DEK wrapping).
func HybridEncapsulateWithDEK(scheme string, recipientPubKeyPath string, dek []byte) (*HybridResult, error) {
	pubKeyBytes, err := os.ReadFile(recipientPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read recipient public key: %w", err)
	}

	pubKey, err := parsePublicKeyPEM(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	switch scheme {
	case HybridX25519AES256GCM:
		return wrapDEKX25519(pubKey, dek)
	case HybridECIESP256:
		return wrapDEKECIESP256(pubKey, dek)
	case HybridRSAOAEP2048, HybridRSAOAEP4096:
		return wrapDEKRSAOAEP(pubKey, scheme, dek)
	case HybridMLKEM768, HybridMLKEM1024:
		pq, ok := pubKey.(*MLKEMPublicKey)
		if !ok {
			return nil, fmt.Errorf("ml-kem: expected MLKEMPublicKey, got %T", pubKey)
		}
		return wrapDEKMLKEM(pq, dek)
	default:
		return nil, fmt.Errorf("unsupported hybrid scheme %q", scheme)
	}
}

// HybridDecapsulate recovers the DEK using the recipient's private key.
func HybridDecapsulate(scheme string, privKeyPath string, ephemeralPubKey, wrappedDEK []byte) ([]byte, error) {
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	privKey, err := parsePrivateKeyPEM(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	switch scheme {
	case HybridX25519AES256GCM:
		return decapsulateX25519(privKey, ephemeralPubKey)
	case HybridECIESP256:
		return decapsulateECIESP256(privKey, ephemeralPubKey)
	case HybridRSAOAEP2048, HybridRSAOAEP4096:
		return decapsulateRSAOAEP(privKey, wrappedDEK)
	case HybridMLKEM768, HybridMLKEM1024:
		pq, ok := privKey.(*MLKEMPrivateKey)
		if !ok {
			return nil, fmt.Errorf("ml-kem: expected MLKEMPrivateKey, got %T", privKey)
		}
		if len(wrappedDEK) == 0 {
			return decapsulateMLKEM(pq, ephemeralPubKey)
		}
		return unwrapDEKMLKEM(pq, ephemeralPubKey, wrappedDEK)
	default:
		return nil, fmt.Errorf("unsupported hybrid scheme %q", scheme)
	}
}

// --- X25519 + HKDF-SHA256 ---

func encapsulateX25519(recipientPub any) (*HybridResult, error) {
	var recipientX25519 *ecdh.PublicKey

	switch k := recipientPub.(type) {
	case *ecdh.PublicKey:
		recipientX25519 = k
	default:
		return nil, fmt.Errorf("x25519: expected X25519 public key, got %T", recipientPub)
	}

	// Generate ephemeral X25519 key pair.
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519: generate ephemeral key: %w", err)
	}

	// ECDH shared secret.
	shared, err := ephPriv.ECDH(recipientX25519)
	if err != nil {
		return nil, fmt.Errorf("x25519: ECDH: %w", err)
	}

	// HKDF-SHA256 to derive DEK.
	dek, err := hkdfDerive(shared, nil, []byte("vaultpack-x25519-dek"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("x25519: HKDF: %w", err)
	}

	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ephPriv.PublicKey().Bytes(),
		Scheme:             HybridX25519AES256GCM,
	}, nil
}

func decapsulateX25519(privKey any, ephemeralPubKeyBytes []byte) ([]byte, error) {
	var recipientPriv *ecdh.PrivateKey

	switch k := privKey.(type) {
	case *ecdh.PrivateKey:
		recipientPriv = k
	default:
		return nil, fmt.Errorf("x25519: expected X25519 private key, got %T", privKey)
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("x25519: parse ephemeral public key: %w", err)
	}

	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("x25519: ECDH: %w", err)
	}

	dek, err := hkdfDerive(shared, nil, []byte("vaultpack-x25519-dek"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("x25519: HKDF: %w", err)
	}

	return dek, nil
}

// --- ECIES P-256 (Ephemeral P-256 → ECDH → HKDF → DEK) ---

func encapsulateECIESP256(recipientPub any) (*HybridResult, error) {
	ecPub, ok := recipientPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ecies-p256: expected ECDSA P-256 public key, got %T", recipientPub)
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ecies-p256: expected P-256, got %s", ecPub.Curve.Params().Name)
	}

	// Convert to ECDH.
	recipientECDH, err := ecPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: convert public key to ECDH: %w", err)
	}

	// Generate ephemeral P-256 key pair.
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: generate ephemeral: %w", err)
	}

	// ECDH.
	shared, err := ephPriv.ECDH(recipientECDH)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: ECDH: %w", err)
	}

	dek, err := hkdfDerive(shared, nil, []byte("vaultpack-ecies-p256-dek"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: HKDF: %w", err)
	}

	// Encode ephemeral public key as uncompressed point.
	ephPubBytes := ephPriv.PublicKey().Bytes()

	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ephPubBytes,
		Scheme:             HybridECIESP256,
	}, nil
}

func decapsulateECIESP256(privKey any, ephemeralPubKeyBytes []byte) ([]byte, error) {
	ecPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecies-p256: expected ECDSA private key, got %T", privKey)
	}

	recipientPrivECDH, err := ecPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: convert private key: %w", err)
	}

	ephPub, err := ecdh.P256().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: parse ephemeral public key: %w", err)
	}

	shared, err := recipientPrivECDH.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: ECDH: %w", err)
	}

	dek, err := hkdfDerive(shared, nil, []byte("vaultpack-ecies-p256-dek"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256: HKDF: %w", err)
	}

	return dek, nil
}

// --- RSA-OAEP-SHA256 key wrapping ---

func encapsulateRSAOAEP(recipientPub any, scheme string) (*HybridResult, error) {
	rsaPub, ok := recipientPub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rsa-oaep: expected RSA public key, got %T", recipientPub)
	}

	// Generate a random DEK.
	dek := make([]byte, AES256KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("rsa-oaep: generate DEK: %w", err)
	}

	// Wrap DEK with RSA-OAEP.
	wrappedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, dek, []byte("vaultpack-dek"))
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep: encrypt DEK: %w", err)
	}

	return &HybridResult{
		DEK:        dek,
		WrappedDEK: wrappedDEK,
		Scheme:     scheme,
	}, nil
}

func decapsulateRSAOAEP(privKey any, wrappedDEK []byte) ([]byte, error) {
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa-oaep: expected RSA private key, got %T", privKey)
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, wrappedDEK, []byte("vaultpack-dek"))
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep: decrypt DEK: %w", err)
	}

	return dek, nil
}

// --- Key generation for hybrid schemes ---

// GenerateHybridKeys generates a private/public key pair for the given hybrid scheme.
// Returns PEM-encoded private and public keys.
func GenerateHybridKeys(scheme string) (privPEM, pubPEM []byte, err error) {
	switch scheme {
	case HybridX25519AES256GCM:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate x25519: %w", err)
		}
		privPEM, err = marshalECDHPrivateKeyPEM(priv)
		if err != nil {
			return nil, nil, err
		}
		pubPEM, err = marshalECDHPublicKeyPEM(priv.PublicKey())
		if err != nil {
			return nil, nil, err
		}
		return privPEM, pubPEM, nil

	case HybridECIESP256:
		// Reuse ECDSA P-256 keygen (ECIES uses the same key type).
		return generateECDSAKeys(elliptic.P256())

	case HybridRSAOAEP2048:
		return generateRSAKeys(2048)

	case HybridRSAOAEP4096:
		return generateRSAKeys(4096)

	case HybridMLKEM768, HybridMLKEM1024:
		return GenerateMLKEMKeys(scheme)

	default:
		return nil, nil, fmt.Errorf("unsupported hybrid scheme %q", scheme)
	}
}

// DetectHybridScheme detects the hybrid scheme from a recipient public key file.
func DetectHybridScheme(pubKeyPath string) (string, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}

	pubKey, err := parsePublicKeyPEM(data)
	if err != nil {
		return "", err
	}

	switch k := pubKey.(type) {
	case *ecdh.PublicKey:
		return HybridX25519AES256GCM, nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return HybridECIESP256, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve for hybrid encryption: %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits <= 2048 {
			return HybridRSAOAEP2048, nil
		}
		return HybridRSAOAEP4096, nil
	case *MLKEMPublicKey:
		return k.Scheme, nil
	default:
		return "", fmt.Errorf("unsupported key type for hybrid encryption: %T", pubKey)
	}
}

// --- PEM helpers for ECDH (X25519) keys ---

func marshalECDHPrivateKeyPEM(key *ecdh.PrivateKey) ([]byte, error) {
	// Go 1.20+ supports marshaling ECDH keys via PKCS#8.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal X25519 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func marshalECDHPublicKeyPEM(key *ecdh.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal X25519 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// parsePublicKeyPEM parses a PEM-encoded public key (supports ECDH, ECDSA, RSA, ML-KEM).
func parsePublicKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if pq, _ := ParseMLKEMPublicKeyPEM(block); pq != nil {
		return pq, nil
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// parsePrivateKeyPEM parses a PEM-encoded private key (supports ECDH, ECDSA, RSA, ML-KEM).
func parsePrivateKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if pq, _ := ParseMLKEMPrivateKeyPEM(block); pq != nil {
		return pq, nil
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// hkdfDerive uses HKDF-SHA256 to derive a key.
func hkdfDerive(secret, salt, info []byte, keyLen int) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := reader.Read(key); err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return key, nil
}

// --- DEK wrapping for multi-recipient ---

// wrapDEKX25519 wraps an existing DEK for an X25519 recipient.
// An ephemeral X25519 ECDH is performed to derive a wrapping key, then the DEK is AES-GCM encrypted.
func wrapDEKX25519(recipientPub any, dek []byte) (*HybridResult, error) {
	recipientX25519, ok := recipientPub.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("x25519-wrap: expected X25519 public key, got %T", recipientPub)
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519-wrap: generate ephemeral: %w", err)
	}

	shared, err := ephPriv.ECDH(recipientX25519)
	if err != nil {
		return nil, fmt.Errorf("x25519-wrap: ECDH: %w", err)
	}

	wrapKey, err := hkdfDerive(shared, nil, []byte("vaultpack-x25519-wrap"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("x25519-wrap: HKDF: %w", err)
	}

	wrapped, err := aesGCMWrap(wrapKey, dek)
	if err != nil {
		return nil, err
	}

	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ephPriv.PublicKey().Bytes(),
		WrappedDEK:         wrapped,
		Scheme:             HybridX25519AES256GCM,
	}, nil
}

// wrapDEKECIESP256 wraps an existing DEK for a P-256 ECIES recipient.
func wrapDEKECIESP256(recipientPub any, dek []byte) (*HybridResult, error) {
	ecPub, ok := recipientPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ecies-p256-wrap: expected ECDSA public key, got %T", recipientPub)
	}

	recipientECDH, err := ecPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-wrap: convert public key: %w", err)
	}

	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-wrap: generate ephemeral: %w", err)
	}

	shared, err := ephPriv.ECDH(recipientECDH)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-wrap: ECDH: %w", err)
	}

	wrapKey, err := hkdfDerive(shared, nil, []byte("vaultpack-ecies-p256-wrap"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-wrap: HKDF: %w", err)
	}

	wrapped, err := aesGCMWrap(wrapKey, dek)
	if err != nil {
		return nil, err
	}

	return &HybridResult{
		DEK:                dek,
		EphemeralPublicKey: ephPriv.PublicKey().Bytes(),
		WrappedDEK:         wrapped,
		Scheme:             HybridECIESP256,
	}, nil
}

// wrapDEKRSAOAEP wraps an existing DEK for an RSA-OAEP recipient.
func wrapDEKRSAOAEP(recipientPub any, scheme string, dek []byte) (*HybridResult, error) {
	rsaPub, ok := recipientPub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rsa-oaep-wrap: expected RSA public key, got %T", recipientPub)
	}

	wrappedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, dek, []byte("vaultpack-dek"))
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep-wrap: encrypt DEK: %w", err)
	}

	return &HybridResult{
		DEK:        dek,
		WrappedDEK: wrappedDEK,
		Scheme:     scheme,
	}, nil
}

// aesGCMWrap encrypts dek with wrapKey using AES-GCM. Returns nonce || ciphertext.
func aesGCMWrap(wrapKey, dek []byte) ([]byte, error) {
	aead, err := NewAEAD(CipherAES256GCM, wrapKey)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-wrap: %w", err)
	}
	nonce, err := GenerateNonce(aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-wrap nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, dek, nil)
	// Return nonce || sealed (nonce + ciphertext + tag)
	return append(nonce, sealed...), nil
}

// aesGCMUnwrap decrypts a wrapped DEK (nonce || ciphertext) with wrapKey using AES-GCM.
func aesGCMUnwrap(wrapKey, wrapped []byte) ([]byte, error) {
	aead, err := NewAEAD(CipherAES256GCM, wrapKey)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-unwrap: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("aes-gcm-unwrap: data too short")
	}
	nonce := wrapped[:nonceSize]
	ciphertext := wrapped[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// HybridDecapsulateWrappedDEK recovers a DEK that was wrapped with HybridEncapsulateWithDEK.
// This is used for multi-recipient decapsulation where ECDH schemes use AES-GCM DEK wrapping.
func HybridDecapsulateWrappedDEK(scheme string, privKeyPath string, ephemeralPubKey, wrappedDEK []byte) ([]byte, error) {
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	privKey, err := parsePrivateKeyPEM(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	switch scheme {
	case HybridX25519AES256GCM:
		return unwrapDEKX25519(privKey, ephemeralPubKey, wrappedDEK)
	case HybridECIESP256:
		return unwrapDEKECIESP256(privKey, ephemeralPubKey, wrappedDEK)
	case HybridRSAOAEP2048, HybridRSAOAEP4096:
		return decapsulateRSAOAEP(privKey, wrappedDEK)
	case HybridMLKEM768, HybridMLKEM1024:
		pq, ok := privKey.(*MLKEMPrivateKey)
		if !ok {
			return nil, fmt.Errorf("ml-kem: expected MLKEMPrivateKey, got %T", privKey)
		}
		if len(wrappedDEK) == 0 {
			return decapsulateMLKEM(pq, ephemeralPubKey)
		}
		return unwrapDEKMLKEM(pq, ephemeralPubKey, wrappedDEK)
	default:
		return nil, fmt.Errorf("unsupported hybrid scheme %q", scheme)
	}
}

func unwrapDEKX25519(privKey any, ephemeralPubKeyBytes, wrappedDEK []byte) ([]byte, error) {
	recipientPriv, ok := privKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("x25519-unwrap: expected X25519 private key, got %T", privKey)
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("x25519-unwrap: parse ephemeral: %w", err)
	}

	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("x25519-unwrap: ECDH: %w", err)
	}

	wrapKey, err := hkdfDerive(shared, nil, []byte("vaultpack-x25519-wrap"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("x25519-unwrap: HKDF: %w", err)
	}

	return aesGCMUnwrap(wrapKey, wrappedDEK)
}

func unwrapDEKECIESP256(privKey any, ephemeralPubKeyBytes, wrappedDEK []byte) ([]byte, error) {
	ecPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecies-p256-unwrap: expected ECDSA private key, got %T", privKey)
	}

	recipientPrivECDH, err := ecPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-unwrap: convert private key: %w", err)
	}

	ephPub, err := ecdh.P256().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-unwrap: parse ephemeral: %w", err)
	}

	shared, err := recipientPrivECDH.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-unwrap: ECDH: %w", err)
	}

	wrapKey, err := hkdfDerive(shared, nil, []byte("vaultpack-ecies-p256-wrap"), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("ecies-p256-unwrap: HKDF: %w", err)
	}

	return aesGCMUnwrap(wrapKey, wrappedDEK)
}

// RecipientKeyFingerprint computes a SHA-256 fingerprint of a recipient's public key file.
func RecipientKeyFingerprint(pubKeyPath string) (string, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	h := sha256.Sum256(block.Bytes)
	return util.B64Encode(h[:]), nil
}
