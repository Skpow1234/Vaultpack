package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func TestProtectWithSign(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	keyFile := filepath.Join(dir, "secret.key")
	privPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	os.WriteFile(inFile, []byte("protect and sign"), 0o600)

	// Generate signing keys.
	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "signing")})
	if err := root.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Protect with --sign.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
		"--sign",
		"--signing-priv", privPath,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("protect --sign: %v", err)
	}

	// Verify bundle has a signature.
	br, err := bundle.Read(bundleFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if br.Signature == nil {
		t.Fatal("expected signature in bundle")
	}

	// Verify the signature is valid.
	root3 := NewRootCmd()
	root3.SetArgs([]string{"verify", "--in", bundleFile, "--pubkey", pubPath})
	if err := root3.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestProtectWithSignThenDecrypt(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.json")
	bundleFile := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")
	outFile := filepath.Join(dir, "data_out.json")

	original := []byte(`{"key":"value","secret":true}`)
	os.WriteFile(inFile, original, 0o600)

	// Generate signing keys.
	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "sign")})
	root.Execute()

	// Protect + sign.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
		"--sign",
		"--signing-priv", filepath.Join(dir, "sign.key"),
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Verify.
	root3 := NewRootCmd()
	root3.SetArgs([]string{"verify", "--in", bundleFile, "--pubkey", filepath.Join(dir, "sign.pub")})
	if err := root3.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Decrypt.
	root4 := NewRootCmd()
	root4.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", outFile, "--key", keyFile})
	if err := root4.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	recovered, _ := os.ReadFile(outFile)
	if string(recovered) != string(original) {
		t.Errorf("got %q, want %q", recovered, original)
	}
}

func TestProtectSignWithoutKey(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"protect", "--in", "f", "--sign"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --sign without --signing-priv")
	}
}
