package audit

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildMerkleRoot(t *testing.T) {
	// Empty leaves should error.
	_, err := BuildMerkleRoot(nil)
	if err == nil {
		t.Fatal("expected error for nil leaves")
	}
	_, err = BuildMerkleRoot([]Leaf{})
	if err == nil {
		t.Fatal("expected error for empty leaves")
	}

	// Single leaf: root is the only node (no hashing step).
	h1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	root, err := BuildMerkleRoot([]Leaf{{Path: "a", Hash: h1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 32 {
		t.Errorf("root length = %d, want 32", len(root))
	}
	if hex.EncodeToString(root) != hex.EncodeToString(h1) {
		t.Error("single leaf root should equal leaf hash")
	}

	// Two leaves: deterministic order by path.
	h2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	root2, err := BuildMerkleRoot([]Leaf{
		{Path: "b", Hash: h2},
		{Path: "a", Hash: h1},
	})
	if err != nil {
		t.Fatal(err)
	}
	root2b, _ := BuildMerkleRoot([]Leaf{
		{Path: "a", Hash: h1},
		{Path: "b", Hash: h2},
	})
	if hex.EncodeToString(root2) != hex.EncodeToString(root2b) {
		t.Error("same leaves in different order should produce same root")
	}
}

func TestSealDir_VerifySealDir_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Create two fake .vpack files.
	for _, name := range []string{"a.vpack", "b.vpack"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("content-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rootHex, leaves, err := SealDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatalf("expected 2 leaves, got %d", len(leaves))
	}
	ok, _, err := VerifySealDir(dir, rootHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify-seal should pass after seal")
	}
	// Tamper: change one file.
	if err := os.WriteFile(filepath.Join(dir, "a.vpack"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok2, _, _ := VerifySealDir(dir, rootHex)
	if ok2 {
		t.Fatal("verify-seal should fail after tampering")
	}
}

func TestSealDir_NoVpackFiles(t *testing.T) {
	dir := t.TempDir()
	_, _, err := SealDir(dir)
	if err == nil {
		t.Fatal("expected error when no .vpack files")
	}
}
