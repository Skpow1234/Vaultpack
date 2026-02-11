package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

// --- split-key / combine-key round-trip ---

func TestSplitKeyCombineKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")

	// Generate a key file.
	key, err := crypto.GenerateKey(crypto.AES256KeySize)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveKeyFile(keyFile, key); err != nil {
		t.Fatal(err)
	}

	// Split into 5 shares, threshold 3.
	root := NewRootCmd()
	root.SetArgs([]string{
		"split-key",
		"--in", keyFile,
		"--shares", "5",
		"--threshold", "3",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("split-key: %v", err)
	}

	// Verify all 5 share files exist.
	for i := 1; i <= 5; i++ {
		p := filepath.Join(dir, "test.key.share"+string(rune('0'+i)))
		if _, err := os.Stat(p); err != nil {
			// Try numeric format.
			p = filepath.Join(dir, "test.key.share"+intToStr(i))
			if _, err2 := os.Stat(p); err2 != nil {
				t.Errorf("share %d not found: %v / %v", i, err, err2)
			}
		}
	}

	// Combine using shares 1, 3, 5 (threshold 3).
	outKey := filepath.Join(dir, "reconstructed.key")
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"combine-key",
		"--share", filepath.Join(dir, "test.key.share1"),
		"--share", filepath.Join(dir, "test.key.share3"),
		"--share", filepath.Join(dir, "test.key.share5"),
		"--out", outKey,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("combine-key: %v", err)
	}

	// Verify the reconstructed key matches the original.
	origData, _ := os.ReadFile(keyFile)
	reconData, _ := os.ReadFile(outKey)
	if !bytes.Equal(origData, reconData) {
		t.Fatal("reconstructed key does not match original")
	}
}

func TestCombineKey_InsufficientShares(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")

	key, _ := crypto.GenerateKey(crypto.AES256KeySize)
	crypto.SaveKeyFile(keyFile, key)

	// Split 5/3.
	root := NewRootCmd()
	root.SetArgs([]string{
		"split-key", "--in", keyFile, "--shares", "5", "--threshold", "3",
	})
	root.Execute()

	// Try combining with only 2 shares (below threshold of 3).
	outKey := filepath.Join(dir, "bad.key")
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"combine-key",
		"--share", filepath.Join(dir, "test.key.share1"),
		"--share", filepath.Join(dir, "test.key.share2"),
		"--out", outKey,
	})
	err := root2.Execute()
	if err == nil {
		t.Fatal("expected error for insufficient shares")
	}
}

// --- protect --split-shares / --split-threshold integration ---

func TestProtect_WithSplitShares(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "secret.txt")
	outFile := filepath.Join(dir, "secret.vpack")
	keyOutFile := filepath.Join(dir, "secret.key")

	os.WriteFile(inFile, []byte("split-shares-protect-test"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outFile,
		"--key-out", keyOutFile,
		"--split-shares", "5",
		"--split-threshold", "3",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect with split: %v", err)
	}

	// The key file should NOT exist (replaced by shares).
	if _, err := os.Stat(keyOutFile); err == nil {
		t.Fatal("key file should not exist when --split-shares is used")
	}

	// All 5 share files should exist.
	for i := 1; i <= 5; i++ {
		p := filepath.Join(dir, "secret.key.share"+intToStr(i))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("share %d not found: %v", i, err)
		}
	}

	// Manifest should have key_splitting metadata.
	br, err := bundle.Read(outFile)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if br.Manifest.KeySplitting == nil {
		t.Fatal("manifest key_splitting should not be nil")
	}
	if br.Manifest.KeySplitting.Scheme != "shamir-gf256" {
		t.Errorf("expected scheme shamir-gf256, got %s", br.Manifest.KeySplitting.Scheme)
	}
	if br.Manifest.KeySplitting.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", br.Manifest.KeySplitting.Threshold)
	}
	if br.Manifest.KeySplitting.Total != 5 {
		t.Errorf("expected total 5, got %d", br.Manifest.KeySplitting.Total)
	}

	// Manifest version should be v2.
	if br.Manifest.Version != bundle.ManifestVersionV2 {
		t.Errorf("expected v2 manifest, got %s", br.Manifest.Version)
	}
}

func TestProtect_SplitShares_DecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outFile := filepath.Join(dir, "data.vpack")
	keyOutFile := filepath.Join(dir, "data.key")
	decryptedFile := filepath.Join(dir, "data.out")
	original := []byte("full round-trip with Shamir split and combine")

	os.WriteFile(inFile, original, 0o600)

	// Protect with split.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outFile,
		"--key-out", keyOutFile,
		"--split-shares", "5",
		"--split-threshold", "3",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Combine shares 2, 4, 5 to reconstruct the key.
	reconKey := filepath.Join(dir, "recovered.key")
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"combine-key",
		"--share", filepath.Join(dir, "data.key.share2"),
		"--share", filepath.Join(dir, "data.key.share4"),
		"--share", filepath.Join(dir, "data.key.share5"),
		"--out", reconKey,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("combine-key: %v", err)
	}

	// Decrypt using the reconstructed key.
	root3 := NewRootCmd()
	root3.SetArgs([]string{
		"decrypt",
		"--in", outFile,
		"--out", decryptedFile,
		"--key", reconKey,
	})
	if err := root3.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	got, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(got, original) {
		t.Fatalf("decrypted content mismatch: got %q", got)
	}
}

func TestProtect_SplitShares_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "j.txt")
	outFile := filepath.Join(dir, "j.vpack")
	keyOutFile := filepath.Join(dir, "j.key")

	os.WriteFile(inFile, []byte("json output test"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outFile,
		"--key-out", keyOutFile,
		"--split-shares", "3",
		"--split-threshold", "2",
		"--json",
	})

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root.Execute()
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("protect: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("json parse: %v\nraw: %s", err, buf.String())
	}

	split, ok := result["key_split"].(map[string]any)
	if !ok {
		t.Fatal("key_split not in JSON output")
	}
	if split["scheme"] != "shamir-gf256" {
		t.Errorf("scheme: %v", split["scheme"])
	}
	if split["threshold"].(float64) != 2 {
		t.Errorf("threshold: %v", split["threshold"])
	}
	if split["total"].(float64) != 3 {
		t.Errorf("total: %v", split["total"])
	}
}

func TestSplitKey_InvalidParams(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")
	key, _ := crypto.GenerateKey(crypto.AES256KeySize)
	crypto.SaveKeyFile(keyFile, key)

	tests := []struct {
		name   string
		shares string
		thresh string
	}{
		{"shares=1", "1", "1"},
		{"thresh>shares", "3", "5"},
		{"shares=0", "0", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCmd()
			root.SetArgs([]string{
				"split-key", "--in", keyFile,
				"--shares", tt.shares, "--threshold", tt.thresh,
			})
			if err := root.Execute(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestInspect_SplitKeyBundle(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outFile := filepath.Join(dir, "data.vpack")
	keyOutFile := filepath.Join(dir, "data.key")

	os.WriteFile(inFile, []byte("inspect split bundle"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect", "--in", inFile, "--out", outFile, "--key-out", keyOutFile,
		"--split-shares", "3", "--split-threshold", "2",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	root2 := NewRootCmd()
	root2.SetArgs([]string{"inspect", "--in", outFile})
	if err := root2.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}

func intToStr(i int) string {
	return fmt.Sprintf("%d", i)
}
