package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func setupSigningTest(t *testing.T) (dir, bundlePath, privPath, pubPath string) {
	t.Helper()
	dir = t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	bundlePath = filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")
	privPath = filepath.Join(dir, "signing.key")
	pubPath = filepath.Join(dir, "signing.pub")

	os.WriteFile(inFile, []byte("sign test data"), 0o600)

	// Create bundle.
	root := NewRootCmd()
	root.SetArgs([]string{"protect", "--in", inFile, "--out", bundlePath, "--key-out", keyFile})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Generate signing keys.
	root2 := NewRootCmd()
	root2.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "signing")})
	if err := root2.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	return
}

func TestSignCmd(t *testing.T) {
	_, bundlePath, privPath, _ := setupSigningTest(t)

	root := NewRootCmd()
	root.SetArgs([]string{"sign", "--in", bundlePath, "--signing-priv", privPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify bundle now contains a signature.
	br, err := bundle.Read(bundlePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if br.Signature == nil {
		t.Error("expected signature in bundle after signing")
	}
}

func TestSignThenVerify(t *testing.T) {
	_, bundlePath, privPath, pubPath := setupSigningTest(t)

	// Sign.
	root := NewRootCmd()
	root.SetArgs([]string{"sign", "--in", bundlePath, "--signing-priv", privPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify.
	root2 := NewRootCmd()
	root2.SetArgs([]string{"verify", "--in", bundlePath, "--pubkey", pubPath})
	if err := root2.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignCmd_MissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing --in", []string{"sign", "--signing-priv", "k"}},
		{"missing --signing-priv", []string{"sign", "--in", "f"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCmd()
			root.SetArgs(tt.args)
			if err := root.Execute(); err == nil {
				t.Error("expected error")
			}
		})
	}
}
