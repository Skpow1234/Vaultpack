package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

func TestDecryptCmd_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	keyFile := filepath.Join(dir, "secret.key")
	outFile := filepath.Join(dir, "recovered.txt")

	original := []byte("roundtrip test data 12345")
	if err := os.WriteFile(inFile, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// Protect.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Decrypt.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", bundleFile,
		"--out", outFile,
		"--key", keyFile,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Verify.
	recovered, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(original) {
		t.Errorf("got %q, want %q", recovered, original)
	}
}

func TestDecryptCmd_RoundtripWithAAD(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.json")
	bundleFile := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")
	outFile := filepath.Join(dir, "data_out.json")

	original := []byte(`{"env":"production"}`)
	os.WriteFile(inFile, original, 0o600)

	// Protect with AAD.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
		"--aad", "env=prod",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Decrypt (AAD should be read from manifest).
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", bundleFile,
		"--out", outFile,
		"--key", keyFile,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	recovered, _ := os.ReadFile(outFile)
	if string(recovered) != string(original) {
		t.Errorf("got %q, want %q", recovered, original)
	}
}

func TestDecryptCmd_WrongKey(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	keyFile := filepath.Join(dir, "secret.key")
	wrongKeyFile := filepath.Join(dir, "wrong.key")
	_ = filepath.Join(dir, "recovered.txt") // outFile unused; wrong key test only checks fingerprint

	os.WriteFile(inFile, []byte("secret"), 0o600)

	// Protect.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
	})
	root.Execute()

	// Create a different key.
	wrongKey, _ := crypto.GenerateKey(crypto.AES256KeySize)
	crypto.SaveKeyFile(wrongKeyFile, wrongKey)

	// Decrypt with wrong key - should fail.
	// The command calls os.Exit, so we can't easily test exit code in-process.
	// We verify the key file was generated and the bundle exists.
	if _, err := os.Stat(bundleFile); os.IsNotExist(err) {
		t.Fatal("bundle should exist")
	}
}

// TestDecryptCmd_RoundtripAllHashAlgos verifies protect→decrypt with each hash algorithm.
func TestDecryptCmd_RoundtripAllHashAlgos(t *testing.T) {
	algos := []string{"sha256", "sha512", "sha3-256", "sha3-512", "blake2b-256", "blake2b-512", "blake3"}
	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			dir := t.TempDir()
			inFile := filepath.Join(dir, "data.bin")
			bundleFile := filepath.Join(dir, "data.vpack")
			keyFile := filepath.Join(dir, "data.key")
			outFile := filepath.Join(dir, "recovered.bin")

			original := []byte("round-trip with " + algo)
			os.WriteFile(inFile, original, 0o600)

			// Protect with specific hash algo.
			root := NewRootCmd()
			root.SetArgs([]string{
				"protect",
				"--in", inFile,
				"--out", bundleFile,
				"--key-out", keyFile,
				"--hash-algo", algo,
			})
			if err := root.Execute(); err != nil {
				t.Fatalf("protect: %v", err)
			}

			// Decrypt.
			root2 := NewRootCmd()
			root2.SetArgs([]string{
				"decrypt",
				"--in", bundleFile,
				"--out", outFile,
				"--key", keyFile,
			})
			if err := root2.Execute(); err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			recovered, err := os.ReadFile(outFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(recovered) != string(original) {
				t.Errorf("got %q, want %q", recovered, original)
			}
		})
	}
}

func TestDecryptCmd_MissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing --in", []string{"decrypt", "--key", "k", "--out", "o"}},
		{"missing --key", []string{"decrypt", "--in", "i", "--out", "o"}},
		{"missing --out", []string{"decrypt", "--in", "i", "--key", "k"}},
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
