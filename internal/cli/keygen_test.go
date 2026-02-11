package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

func TestKeygenCmd(t *testing.T) {
	dir := t.TempDir()
	outPrefix := filepath.Join(dir, "signing")

	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", outPrefix})
	if err := root.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	privPath := outPrefix + ".key"
	pubPath := outPrefix + ".pub"

	// Verify files exist.
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		t.Fatal("private key file not created")
	}
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Fatal("public key file not created")
	}

	// Verify keys are loadable via the new PEM API.
	priv, detectedAlgo, err := crypto.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}
	if detectedAlgo != crypto.SignAlgoEd25519 {
		t.Errorf("expected ed25519, got %s", detectedAlgo)
	}

	pub, pubAlgo, err := crypto.LoadAnyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}
	if pubAlgo != crypto.SignAlgoEd25519 {
		t.Errorf("expected ed25519, got %s", pubAlgo)
	}

	// Verify sign + verify round-trip works.
	msg := []byte("keygen test")
	sig, err := crypto.SignMessage(priv, detectedAlgo, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := crypto.VerifySignature(pub, pubAlgo, msg, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("generated keys cannot sign/verify")
	}
}

// TestKeygenCmd_AllAlgos generates and validates key pairs for all algorithms.
func TestKeygenCmd_AllAlgos(t *testing.T) {
	for _, algo := range crypto.SupportedSignAlgos {
		t.Run(algo, func(t *testing.T) {
			dir := t.TempDir()
			outPrefix := filepath.Join(dir, "key")

			root := NewRootCmd()
			root.SetArgs([]string{"keygen", "--out", outPrefix, "--algo", algo})
			if err := root.Execute(); err != nil {
				t.Fatalf("keygen: %v", err)
			}

			privPath := outPrefix + ".key"
			pubPath := outPrefix + ".pub"

			priv, detectedAlgo, err := crypto.LoadPrivateKey(privPath)
			if err != nil {
				t.Fatalf("load private: %v", err)
			}
			if detectedAlgo != algo {
				t.Errorf("expected %s, got %s", algo, detectedAlgo)
			}

			pub, pubAlgo, err := crypto.LoadAnyPublicKey(pubPath)
			if err != nil {
				t.Fatalf("load public: %v", err)
			}
			if pubAlgo != algo {
				t.Errorf("expected %s, got %s", algo, pubAlgo)
			}

			msg := []byte("round-trip test for " + algo)
			sig, err := crypto.SignMessage(priv, detectedAlgo, msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			valid, err := crypto.VerifySignature(pub, pubAlgo, msg, sig)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !valid {
				t.Error("sign/verify failed for " + algo)
			}
		})
	}
}

func TestKeygenCmd_MissingOut(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"keygen"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error when --out is missing")
	}
}
