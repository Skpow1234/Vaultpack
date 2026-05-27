package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEmptyTreeRoot(t *testing.T) {
	tree := NewMerkleTree()
	root := tree.Root()
	want := sha256.Sum256(nil)
	if !bytes.Equal(root, want[:]) {
		t.Errorf("empty root = %x want %x", root, want[:])
	}
}

func TestLeafHashDomainSeparation(t *testing.T) {
	data := []byte("abc")
	lh := LeafHash(data)
	// Make sure prefix is included, i.e. SHA256(data) != LeafHash(data).
	bare := sha256.Sum256(data)
	if bytes.Equal(bare[:], lh) {
		t.Fatal("leaf hash equal to bare SHA256 — prefix missing")
	}
}

// Reference: RFC 6962 §2.1 worked example for [d0,d1,d2,d3].
// We don't reproduce the official test vectors here (cosign/google CT
// repos have those), but we do verify that the same set of leaves
// always produces the same root and that Append is incremental.
func TestRootDeterminism(t *testing.T) {
	a := NewMerkleTree()
	b := NewMerkleTree()
	for _, s := range []string{"alpha", "beta", "gamma", "delta", "epsilon"} {
		a.Append([]byte(s))
		b.Append([]byte(s))
	}
	if !bytes.Equal(a.Root(), b.Root()) {
		t.Fatal("roots diverge for identical inputs")
	}
}

func TestInclusionProof_RoundTrip(t *testing.T) {
	tree := NewMerkleTree()
	leaves := [][]byte{}
	for i := 0; i < 7; i++ {
		data := []byte{byte(i)}
		tree.Append(data)
		leaves = append(leaves, LeafHash(data))
	}
	root := tree.Root()

	for i := 0; i < len(leaves); i++ {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if err := VerifyInclusion(leaves[i], i, len(leaves), proof, root); err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
	}
}

func TestInclusionProof_TamperedRootFails(t *testing.T) {
	tree := NewMerkleTree()
	for i := 0; i < 5; i++ {
		tree.Append([]byte{byte(i)})
	}
	proof, _ := tree.InclusionProof(2)
	leaf := LeafHash([]byte{2})
	root := tree.Root()
	// Flip one bit in the root.
	bad := append([]byte(nil), root...)
	bad[0] ^= 0x01
	if err := VerifyInclusion(leaf, 2, 5, proof, bad); err == nil {
		t.Fatal("expected verification to fail with tampered root")
	}
}

func TestInclusionProof_WrongLeafFails(t *testing.T) {
	tree := NewMerkleTree()
	for i := 0; i < 5; i++ {
		tree.Append([]byte{byte(i)})
	}
	proof, _ := tree.InclusionProof(2)
	// Use the wrong leaf hash.
	wrong := LeafHash([]byte{99})
	if err := VerifyInclusion(wrong, 2, 5, proof, tree.Root()); err == nil {
		t.Fatal("expected verification to fail with wrong leaf")
	}
}

func TestConsistencyProof_RoundTrip(t *testing.T) {
	tree := NewMerkleTree()
	roots := [][]byte{}
	for i := 0; i < 8; i++ {
		tree.Append([]byte{byte(i)})
		roots = append(roots, tree.Root())
	}
	// For each (m, n) pair with 0 < m < n, the proof should verify.
	for m := 1; m < len(roots); m++ {
		for n := m + 1; n <= len(roots); n++ {
			// Build a tree of size n and ask for the proof from m to n.
			tn, err := LoadMerkleTree(tree.leaves[:n])
			if err != nil {
				t.Fatal(err)
			}
			proof, err := tn.ConsistencyProof(m)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d,%d): %v", m, n, err)
			}
			if err := VerifyConsistency(m, n, roots[m-1], roots[n-1], proof); err != nil {
				t.Fatalf("VerifyConsistency(m=%d,n=%d): %v", m, n, err)
			}
		}
	}
}

func TestConsistencyProof_Tampered(t *testing.T) {
	tree := NewMerkleTree()
	for i := 0; i < 5; i++ {
		tree.Append([]byte{byte(i)})
	}
	rootAt3 := func() []byte {
		t3, _ := LoadMerkleTree(tree.leaves[:3])
		return t3.Root()
	}()
	rootAt5 := tree.Root()
	proof, err := tree.ConsistencyProof(3)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate one proof hash.
	if len(proof) > 0 {
		proof[0] = append([]byte(nil), proof[0]...)
		proof[0][0] ^= 0xFF
	}
	if err := VerifyConsistency(3, 5, rootAt3, rootAt5, proof); err == nil {
		t.Fatal("expected tampered consistency proof to fail")
	}
}

func TestLoadAndAppend(t *testing.T) {
	t1 := NewMerkleTree()
	for _, s := range []string{"x", "y", "z"} {
		t1.Append([]byte(s))
	}
	leaves := make([][]byte, 0, t1.Size())
	for i := 0; i < t1.Size(); i++ {
		leaves = append(leaves, t1.leaves[i])
	}
	t2, err := LoadMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(t1.Root(), t2.Root()) {
		t.Fatalf("loaded tree root mismatch: %s vs %s",
			hex.EncodeToString(t1.Root()), hex.EncodeToString(t2.Root()))
	}
}
