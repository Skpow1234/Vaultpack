package vaultpack

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

func TestProtectDecrypt_Hybrid_RoundTrip(t *testing.T) {
	privPEM, pubPEM, err := crypto.GenerateHybridKeys("x25519-aes-256-gcm")
	if err != nil {
		t.Fatalf("GenerateHybridKeys: %v", err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "hybrid.vpack")
	plaintext := []byte("hybrid sdk round-trip")

	_, err = Protect(ProtectOptions{
		Plaintext:  plaintext,
		OutputPath: bundlePath,
		Recipients: []Recipient{{PublicKeyPEM: pubPEM}},
	})
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	dec, err := Decrypt(DecryptOptions{
		InputPath:  bundlePath,
		PrivateKey: privPEM,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec.Plaintext, plaintext) {
		t.Fatal("plaintext mismatch after hybrid round-trip")
	}
}
