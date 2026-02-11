package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func TestProtectCmd_ProducesBundle(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "secret.txt")
	outFile := filepath.Join(dir, "secret.vpack")
	keyFile := filepath.Join(dir, "secret.key")

	if err := os.WriteFile(inFile, []byte("my secret data"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outFile,
		"--key-out", keyFile,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Verify bundle exists and is readable.
	result, err := bundle.Read(outFile)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if result.Manifest.Version != bundle.ManifestVersion {
		t.Errorf("version: %q", result.Manifest.Version)
	}
	if result.Manifest.Input.Name != "secret.txt" {
		t.Errorf("input name: %q", result.Manifest.Input.Name)
	}
	if result.Manifest.Input.Size != 14 {
		t.Errorf("input size: %d", result.Manifest.Input.Size)
	}

	// Verify key file exists and has correct length.
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(keyData) == 0 {
		t.Error("key file is empty")
	}
}

func TestProtectCmd_MissingIn(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"protect"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --in is missing")
	}
}

func TestProtectCmd_WithAAD(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.json")
	outFile := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")

	os.WriteFile(inFile, []byte(`{"key":"value"}`), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outFile,
		"--key-out", keyFile,
		"--aad", "env=prod",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result, err := bundle.Read(outFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if result.Manifest.Encryption.AADB64 == nil {
		t.Error("expected non-nil AAD in manifest")
	}
}
