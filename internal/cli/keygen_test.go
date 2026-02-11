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

	// Verify keys are loadable.
	priv, err := crypto.LoadSigningKey(privPath)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}
	pub, err := crypto.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}

	// Verify keys work together.
	msg := []byte("keygen test")
	sig := crypto.Sign(priv, msg)
	if !crypto.Verify(pub, msg, sig) {
		t.Error("generated keys cannot sign/verify")
	}
}

func TestKeygenCmd_MissingOut(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"keygen"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error when --out is missing")
	}
}
