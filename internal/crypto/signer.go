package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// Signing algorithm names.
const (
	SignAlgoEd25519    = "ed25519"
	SignAlgoECDSAP256  = "ecdsa-p256"
	SignAlgoECDSAP384  = "ecdsa-p384"
	SignAlgoRSAPSS2048 = "rsa-pss-2048"
	SignAlgoRSAPSS4096 = "rsa-pss-4096"
	SignAlgoMLDSA65    = "ml-dsa-65"
	SignAlgoMLDSA87    = "ml-dsa-87"
)

// SupportedSignAlgos is the list of supported signing algorithm names.
var SupportedSignAlgos = []string{
	SignAlgoEd25519,
	SignAlgoECDSAP256,
	SignAlgoECDSAP384,
	SignAlgoRSAPSS2048,
	SignAlgoRSAPSS4096,
	SignAlgoMLDSA65,
	SignAlgoMLDSA87,
}

// SupportedSignAlgo checks whether the given signing algorithm is supported.
func SupportedSignAlgo(algo string) bool {
	for _, a := range SupportedSignAlgos {
		if a == algo {
			return true
		}
	}
	return false
}

// GenerateSigningKeys generates a private/public key pair for the named algorithm.
// Returns (private key bytes in PEM, public key bytes in PEM, error).
// For Ed25519, also supports the legacy raw format.
func GenerateSigningKeys(algo string) (privPEM, pubPEM []byte, err error) {
	switch algo {
	case SignAlgoEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ed25519: %w", err)
		}
		privPEM, err = marshalPrivateKeyPEM(priv)
		if err != nil {
			return nil, nil, err
		}
		pubPEM, err = marshalPublicKeyPEM(pub)
		if err != nil {
			return nil, nil, err
		}
		return privPEM, pubPEM, nil

	case SignAlgoECDSAP256:
		return generateECDSAKeys(elliptic.P256())

	case SignAlgoECDSAP384:
		return generateECDSAKeys(elliptic.P384())

	case SignAlgoRSAPSS2048:
		return generateRSAKeys(2048)

	case SignAlgoRSAPSS4096:
		return generateRSAKeys(4096)

	case SignAlgoMLDSA65, SignAlgoMLDSA87:
		return GenerateMLDSAKeys(algo)

	default:
		return nil, nil, fmt.Errorf("unsupported signing algorithm %q", algo)
	}
}

func generateECDSAKeys(curve elliptic.Curve) (privPEM, pubPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ecdsa: %w", err)
	}
	privPEM, err = marshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, err
	}
	pubPEM, err = marshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privPEM, pubPEM, nil
}

func generateRSAKeys(bits int) (privPEM, pubPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa-%d: %w", bits, err)
	}
	privPEM, err = marshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, err
	}
	pubPEM, err = marshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privPEM, pubPEM, nil
}

// marshalPrivateKeyPEM encodes a private key to PKCS#8 PEM format.
func marshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// marshalPublicKeyPEM encodes a public key to PKIX PEM format.
func marshalPublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// SaveKeyPEM writes PEM-encoded key data to a file.
func SaveKeyPEM(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

// LoadPrivateKey loads a private key from a PEM file or legacy Ed25519 raw format.
// Returns the parsed crypto.Signer and the detected algorithm name.
func LoadPrivateKey(path string) (crypto.Signer, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("load private key: %w", err)
	}

	content := strings.TrimSpace(string(data))

	// Legacy Ed25519 raw format: "ed25519-priv:<base64>"
	if strings.HasPrefix(content, "ed25519-priv:") {
		raw, err := util.B64Decode(strings.TrimPrefix(content, "ed25519-priv:"))
		if err != nil {
			return nil, "", fmt.Errorf("decode legacy ed25519 key: %w", err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, "", fmt.Errorf("invalid ed25519 private key size: got %d", len(raw))
		}
		return ed25519.PrivateKey(raw), SignAlgoEd25519, nil
	}

	// PEM format.
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found in %s", path)
	}

	if mldsa, _ := ParseMLDSAPrivateKeyPEM(block); mldsa != nil {
		algo := SignAlgoMLDSA65
		if block.Type == pemTypeMLDSA87Priv {
			algo = SignAlgoMLDSA87
		}
		return mldsa, algo, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, SignAlgoEd25519, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return k, SignAlgoECDSAP256, nil
		case elliptic.P384():
			return k, SignAlgoECDSAP384, nil
		default:
			return nil, "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		switch {
		case bits <= 2048:
			return k, SignAlgoRSAPSS2048, nil
	default:
		return k, SignAlgoRSAPSS4096, nil
	}
	default:
		return nil, "", fmt.Errorf("unsupported private key type: %T", key)
	}
}

// LoadAnyPublicKey loads a public key from a PEM file or legacy Ed25519 raw format.
// Returns the parsed crypto.PublicKey and the detected algorithm name.
func LoadAnyPublicKey(path string) (crypto.PublicKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("load public key: %w", err)
	}

	content := strings.TrimSpace(string(data))

	// Legacy Ed25519 raw format: "ed25519-pub:<base64>"
	if strings.HasPrefix(content, "ed25519-pub:") {
		raw, err := util.B64Decode(strings.TrimPrefix(content, "ed25519-pub:"))
		if err != nil {
			return nil, "", fmt.Errorf("decode legacy ed25519 public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid ed25519 public key size: got %d", len(raw))
		}
		return ed25519.PublicKey(raw), SignAlgoEd25519, nil
	}

	// PEM format.
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found in %s", path)
	}

	if mldsa, _ := ParseMLDSAPublicKeyPEM(block); mldsa != nil {
		algo := SignAlgoMLDSA65
		if block.Type == pemTypeMLDSA87Pub {
			algo = SignAlgoMLDSA87
		}
		return mldsa, algo, nil
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key: %w", err)
	}

	switch k := key.(type) {
	case ed25519.PublicKey:
		return k, SignAlgoEd25519, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return k, SignAlgoECDSAP256, nil
		case elliptic.P384():
			return k, SignAlgoECDSAP384, nil
		default:
			return nil, "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch {
		case bits <= 2048:
			return k, SignAlgoRSAPSS2048, nil
		default:
			return k, SignAlgoRSAPSS4096, nil
		}
	default:
		return nil, "", fmt.Errorf("unsupported public key type: %T", key)
	}
}

// SignMessage signs a message using the given private key and algorithm.
func SignMessage(signer crypto.Signer, algo string, message []byte) ([]byte, error) {
	switch algo {
	case SignAlgoEd25519:
		edKey, ok := signer.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key type mismatch: expected ed25519, got %T", signer)
		}
		return ed25519.Sign(edKey, message), nil

	case SignAlgoECDSAP256, SignAlgoECDSAP384:
		ecKey, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key type mismatch: expected ecdsa, got %T", signer)
		}
		hash := sha256.Sum256(message)
		return ecdsa.SignASN1(rand.Reader, ecKey, hash[:])

	case SignAlgoRSAPSS2048, SignAlgoRSAPSS4096:
		rsaKey, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key type mismatch: expected rsa, got %T", signer)
		}
		hash := sha256.Sum256(message)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		return rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hash[:], opts)

	case SignAlgoMLDSA65, SignAlgoMLDSA87:
		mldsa, ok := signer.(*MLDSASigner)
		if !ok {
			return nil, fmt.Errorf("key type mismatch: expected ML-DSA signer, got %T", signer)
		}
		return mldsa.Scheme.Sign(mldsa.Key, message, nil), nil

	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", algo)
	}
}

// VerifySignature verifies a signature using the given public key and algorithm.
func VerifySignature(pubKey crypto.PublicKey, algo string, message, sig []byte) (bool, error) {
	switch algo {
	case SignAlgoEd25519:
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("key type mismatch: expected ed25519, got %T", pubKey)
		}
		return ed25519.Verify(edKey, message, sig), nil

	case SignAlgoECDSAP256, SignAlgoECDSAP384:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key type mismatch: expected ecdsa, got %T", pubKey)
		}
		hash := sha256.Sum256(message)
		return ecdsa.VerifyASN1(ecKey, hash[:], sig), nil

	case SignAlgoRSAPSS2048, SignAlgoRSAPSS4096:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key type mismatch: expected rsa, got %T", pubKey)
		}
		hash := sha256.Sum256(message)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		err := rsa.VerifyPSS(rsaKey, crypto.SHA256, hash[:], sig, opts)
		return err == nil, nil

	case SignAlgoMLDSA65, SignAlgoMLDSA87:
		mldsa, ok := pubKey.(*MLDSAPublicKey)
		if !ok {
			return false, fmt.Errorf("key type mismatch: expected ML-DSA public key, got %T", pubKey)
		}
		return VerifyMLDSA(mldsa, message, sig), nil

	default:
		return false, fmt.Errorf("unsupported signing algorithm %q", algo)
	}
}
