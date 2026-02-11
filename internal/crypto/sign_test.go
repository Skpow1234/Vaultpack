package crypto

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestGenerateSigningKeyPair(t *testing.T) {
	priv, pub, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, pub, _ := GenerateSigningKeyPair()
	message := []byte("hello vaultpack signing")

	sig := Sign(priv, message)
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !Verify(pub, message, sig) {
		t.Error("valid signature failed verification")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	priv, pub, _ := GenerateSigningKeyPair()
	sig := Sign(priv, []byte("original"))

	if Verify(pub, []byte("tampered"), sig) {
		t.Error("verification should fail for wrong message")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	priv1, _, _ := GenerateSigningKeyPair()
	_, pub2, _ := GenerateSigningKeyPair()

	message := []byte("test")
	sig := Sign(priv1, message)

	if Verify(pub2, message, sig) {
		t.Error("verification should fail for wrong public key")
	}
}

func TestSigningKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	priv, pub, _ := GenerateSigningKeyPair()

	if err := SaveSigningKey(privPath, priv); err != nil {
		t.Fatalf("save private: %v", err)
	}
	if err := SavePublicKey(pubPath, pub); err != nil {
		t.Fatalf("save public: %v", err)
	}

	loadedPriv, err := LoadSigningKey(privPath)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}
	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}

	if !priv.Equal(loadedPriv) {
		t.Error("private key mismatch")
	}
	if !pub.Equal(loadedPub) {
		t.Error("public key mismatch")
	}

	// Verify loaded keys work for sign/verify.
	message := []byte("roundtrip")
	sig := Sign(loadedPriv, message)
	if !Verify(loadedPub, message, sig) {
		t.Error("loaded keys cannot sign/verify")
	}
}

func TestBuildSigningMessage(t *testing.T) {
	manifest := []byte(`{"version":"v1"}`)
	payloadHash := []byte("abcdef0123456789")

	msg := BuildSigningMessage(manifest, payloadHash)
	if len(msg) != len(manifest)+len(payloadHash) {
		t.Errorf("message length: got %d, want %d", len(msg), len(manifest)+len(payloadHash))
	}
}
