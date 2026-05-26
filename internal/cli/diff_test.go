package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func TestDiff_IdenticalBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	root := NewRootCmd()
	root.SetArgs([]string{"diff", "--a", bundlePath, "--b", bundlePath})
	if err := root.Execute(); err != nil {
		t.Fatalf("diff identical: %v", err)
	}
}

func TestDiff_MissingArgs(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"diff", "--a", "x.vpack"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error when --b is missing")
	}
}

func TestDiffManifests_PlaintextDifference(t *testing.T) {
	dir := t.TempDir()
	inA := filepath.Join(dir, "a.txt")
	inB := filepath.Join(dir, "b.txt")
	os.WriteFile(inA, []byte("aaaa"), 0o600)
	os.WriteFile(inB, []byte("bbbb"), 0o600)

	pathA := filepath.Join(dir, "a.vpack")
	pathB := filepath.Join(dir, "b.vpack")
	keyA := filepath.Join(dir, "a.key")
	keyB := filepath.Join(dir, "b.key")

	root1 := NewRootCmd()
	root1.SetArgs([]string{"protect", "--in", inA, "--out", pathA, "--key-out", keyA})
	if err := root1.Execute(); err != nil {
		t.Fatalf("protect a: %v", err)
	}
	root2 := NewRootCmd()
	root2.SetArgs([]string{"protect", "--in", inB, "--out", pathB, "--key-out", keyB})
	if err := root2.Execute(); err != nil {
		t.Fatalf("protect b: %v", err)
	}

	mA, _, _ := bundle.ReadManifestOnly(pathA)
	mB, _, _ := bundle.ReadManifestOnly(pathB)

	diffs := diffManifests(mA, mB, true, true)
	if len(diffs) == 0 {
		t.Fatal("expected diffs for different plaintext")
	}

	foundPlaintext := false
	for _, d := range diffs {
		if strings.HasPrefix(d.Field, "plaintext_hash") {
			foundPlaintext = true
			break
		}
	}
	if !foundPlaintext {
		t.Errorf("expected plaintext_hash diff, got: %+v", diffs)
	}
}

func TestDiffManifests_IgnoreNonce(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.txt")
	os.WriteFile(in, []byte("same data"), 0o600)

	pathA := filepath.Join(dir, "a.vpack")
	pathB := filepath.Join(dir, "b.vpack")
	keyA := filepath.Join(dir, "a.key")
	keyB := filepath.Join(dir, "b.key")

	// Two encryptions of the same plaintext produce different nonces and tags
	// but the same plaintext hash. With --ignore-nonce, the only diff should
	// be created_at (and any other timestamps), key_id, ciphertext.size, etc.
	root1 := NewRootCmd()
	root1.SetArgs([]string{"protect", "--in", in, "--out", pathA, "--key-out", keyA})
	if err := root1.Execute(); err != nil {
		t.Fatalf("protect a: %v", err)
	}
	root2 := NewRootCmd()
	root2.SetArgs([]string{"protect", "--in", in, "--out", pathB, "--key-out", keyB})
	if err := root2.Execute(); err != nil {
		t.Fatalf("protect b: %v", err)
	}

	mA, _, _ := bundle.ReadManifestOnly(pathA)
	mB, _, _ := bundle.ReadManifestOnly(pathB)

	diffs := diffManifests(mA, mB, true, true)
	// Plaintext hash should be identical.
	for _, d := range diffs {
		if strings.HasPrefix(d.Field, "plaintext_hash") {
			t.Errorf("expected no plaintext_hash diff for same plaintext, got %+v", d)
		}
		if d.Field == "encryption.nonce_b64" || d.Field == "encryption.tag_b64" {
			t.Errorf("expected --ignore-nonce to skip %s, got %+v", d.Field, d)
		}
	}
}
