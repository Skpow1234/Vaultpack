package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Leaf represents one file's contribution to the Merkle tree (path + content hash).
type Leaf struct {
	Path string // relative or absolute path
	Hash []byte // SHA-256 of file content
}

// BuildMerkleRoot computes a deterministic Merkle root from a sorted list of leaves.
// Leaves are sorted by Path; then a binary Merkle tree is built (hash(L||R) for pairs).
func BuildMerkleRoot(leaves []Leaf) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("no leaves for Merkle tree")
	}
	sorted := make([]Leaf, len(leaves))
	copy(sorted, leaves)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	// Leaf hashes: H(path || hash) for canonical ordering, or just use hash for simplicity.
	// Design says "Merkle root over all bundle hashes" - so we use content hash as leaf.
	nodes := make([][]byte, len(sorted))
	for i := range sorted {
		nodes[i] = make([]byte, len(sorted[i].Hash))
		copy(nodes[i], sorted[i].Hash)
	}

	for len(nodes) > 1 {
		var next [][]byte
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				h := sha256.Sum256(append(nodes[i], nodes[i+1]...))
				next = append(next, h[:])
			} else {
				// Odd: duplicate last node to pair
				h := sha256.Sum256(append(nodes[i], nodes[i]...))
				next = append(next, h[:])
			}
		}
		nodes = next
	}
	return nodes[0], nil
}

// HashFile reads the file and returns SHA-256 digest.
func HashFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// SealDir walks dir for *.vpack files, hashes each, and returns the Merkle root (hex).
func SealDir(dir string) (rootHex string, leaves []Leaf, err error) {
	var paths []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".vpack" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	sort.Strings(paths)

	leaves = make([]Leaf, 0, len(paths))
	for _, p := range paths {
		hash, err := HashFile(p)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", p, err)
		}
		rel, _ := filepath.Rel(dir, p)
		leaves = append(leaves, Leaf{Path: rel, Hash: hash})
	}
	if len(leaves) == 0 {
		return "", nil, fmt.Errorf("no .vpack files in %s", dir)
	}
	root, err := BuildMerkleRoot(leaves)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(root), leaves, nil
}

// VerifySealDir recomputes the Merkle root for dir and compares to expectedRootHex.
func VerifySealDir(dir, expectedRootHex string) (bool, []Leaf, error) {
	rootHex, leaves, err := SealDir(dir)
	if err != nil {
		return false, nil, err
	}
	return rootHex == expectedRootHex, leaves, nil
}
