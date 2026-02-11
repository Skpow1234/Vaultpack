package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func TestCompressProtectDecrypt_Gzip(t *testing.T) {
	testCompressRoundTrip(t, "gzip")
}

func TestCompressProtectDecrypt_Zstd(t *testing.T) {
	testCompressRoundTrip(t, "zstd")
}

func testCompressRoundTrip(t *testing.T, algo string) {
	t.Helper()
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")
	decFile := filepath.Join(dir, "data.dec.txt")

	// Create a repetitive file (compresses well).
	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	if err := os.WriteFile(inFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	// Protect with compression.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--key-out", keyFile,
		"--compress", algo,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Inspect: verify compression metadata.
	br, err := bundle.Read(outVpack)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if br.Manifest.Compress == nil {
		t.Fatal("expected compression metadata in manifest")
	}
	if br.Manifest.Compress.Algo != algo {
		t.Errorf("compression algo: got %q, want %q", br.Manifest.Compress.Algo, algo)
	}
	if br.Manifest.Compress.OriginalSize != int64(len(payload)) {
		t.Errorf("original size: got %d, want %d", br.Manifest.Compress.OriginalSize, len(payload))
	}

	// Decrypt.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", outVpack,
		"--out", decFile,
		"--key", keyFile,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Verify plaintext matches.
	decData, err := os.ReadFile(decFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != string(payload) {
		t.Error("decrypted data does not match original")
	}
}

func TestCompressProtect_ManifestVersion(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")

	os.WriteFile(inFile, []byte("hello"), 0o600)

	// With compression, should be v2.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--key-out", keyFile,
		"--compress", "gzip",
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	br, err := bundle.Read(outVpack)
	if err != nil {
		t.Fatal(err)
	}
	if br.Manifest.Version != bundle.ManifestVersionV2 {
		t.Errorf("expected v2 for compressed bundle, got %s", br.Manifest.Version)
	}
}

func TestNoCompress_ManifestVersionV1(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")

	os.WriteFile(inFile, []byte("hello"), 0o600)

	// Without compression, should be v1.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--key-out", keyFile,
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	br, err := bundle.Read(outVpack)
	if err != nil {
		t.Fatal(err)
	}
	if br.Manifest.Version != bundle.ManifestVersionV1 {
		t.Errorf("expected v1 for non-compressed bundle, got %s", br.Manifest.Version)
	}
}

func TestInspect_CompressedBundle(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	keyFile := filepath.Join(dir, "data.key")

	os.WriteFile(inFile, []byte("compress me"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--key-out", keyFile,
		"--compress", "zstd",
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	// Inspect should succeed.
	root2 := NewRootCmd()
	root2.SetArgs([]string{"inspect", "--in", outVpack})
	if err := root2.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}
