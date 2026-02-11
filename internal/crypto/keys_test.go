package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	key, err := GenerateKey(AES256KeySize)
	if err != nil {
		t.Fatal(err)
	}

	if err := SaveKeyFile(keyPath, key); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(loaded) != AES256KeySize {
		t.Errorf("key size: got %d, want %d", len(loaded), AES256KeySize)
	}
	for i := range key {
		if key[i] != loaded[i] {
			t.Fatal("loaded key does not match original")
		}
	}
}

func TestKeyFileHasPrefix(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	key, _ := GenerateKey(AES256KeySize)
	_ = SaveKeyFile(keyPath, key)

	data, _ := os.ReadFile(keyPath)
	if len(data) < 4 || string(data[:4]) != "b64:" {
		t.Errorf("key file should start with 'b64:', got: %q", string(data[:10]))
	}
}

func TestLoadKeyFileInvalidLength(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")
	// Write a key that's too short (16 bytes instead of 32).
	os.WriteFile(keyPath, []byte("b64:AAAAAAAAAAAAAAAAAAAAAA==\n"), 0o600)

	_, err := LoadKeyFile(keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestKeyFingerprint(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)
	algo, digest := KeyFingerprint(key)
	if algo != "sha256" {
		t.Errorf("algo: got %q, want sha256", algo)
	}
	if len(digest) == 0 {
		t.Error("empty digest")
	}

	// Same key should produce same fingerprint.
	algo2, digest2 := KeyFingerprint(key)
	if algo != algo2 || digest != digest2 {
		t.Error("fingerprint is not deterministic")
	}
}
