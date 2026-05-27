// Package repo implements a tamper-evident, append-only repository of
// .vpack bundles. Each `repo add` appends a new leaf to an RFC 6962-style
// Merkle history tree, signs the resulting root, and (optionally) anchors
// it in a Sigstore Rekor log. `repo verify` walks the log forward and
// recomputes every root, ensuring the chain is intact and every entry's
// signature still verifies.
package repo

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domain-separation prefixes (RFC 6962 §2.1). They prevent second-preimage
// attacks where a leaf hash could be presented as an internal node, or
// vice versa.
var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// HashSize is the byte length of every node hash in the tree.
const HashSize = sha256.Size

// LeafHash computes the leaf hash of an arbitrary byte slice. The result
// is what gets appended to the history tree.
//
//	H_leaf = SHA-256(0x00 || data)
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash computes the internal node hash from a left + right child hash.
//
//	H_node = SHA-256(0x01 || left || right)
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(nodePrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleTree is a deterministic, append-only RFC 6962 history tree.
//
// Construction follows the canonical algorithm: a tree of size n is the
// hash of the largest left subtree of size k (where k is the largest
// power of two strictly less than n, or k=1 when n=1) and the right
// subtree containing the remaining n-k leaves. The empty tree has the
// canonical hash SHA-256("").
//
// The tree stores only leaf hashes; internal hashes are recomputed on
// demand. For VaultPack repos the leaf count is small (one per `repo add`),
// so memory cost is negligible.
type MerkleTree struct {
	leaves [][]byte
}

// NewMerkleTree returns an empty tree.
func NewMerkleTree() *MerkleTree { return &MerkleTree{} }

// LoadMerkleTree constructs a tree from an ordered slice of pre-computed
// leaf hashes (each must be exactly HashSize bytes).
func LoadMerkleTree(leafHashes [][]byte) (*MerkleTree, error) {
	for i, h := range leafHashes {
		if len(h) != HashSize {
			return nil, fmt.Errorf("leaf %d: want %d bytes, got %d", i, HashSize, len(h))
		}
	}
	t := &MerkleTree{leaves: make([][]byte, len(leafHashes))}
	for i, h := range leafHashes {
		t.leaves[i] = append([]byte(nil), h...)
	}
	return t, nil
}

// Size returns the number of leaves currently in the tree.
func (t *MerkleTree) Size() int { return len(t.leaves) }

// Append adds a new leaf (the data is hashed with LeafHash) and returns
// the new root.
func (t *MerkleTree) Append(data []byte) []byte {
	t.leaves = append(t.leaves, LeafHash(data))
	return t.Root()
}

// AppendLeaf adds a pre-computed leaf hash and returns the new root.
func (t *MerkleTree) AppendLeaf(leafHash []byte) ([]byte, error) {
	if len(leafHash) != HashSize {
		return nil, fmt.Errorf("AppendLeaf: want %d bytes, got %d", HashSize, len(leafHash))
	}
	t.leaves = append(t.leaves, append([]byte(nil), leafHash...))
	return t.Root(), nil
}

// Root returns the current root hash. For the empty tree, it is the
// SHA-256 of the empty string (RFC 6962 §2.1).
func (t *MerkleTree) Root() []byte {
	if len(t.leaves) == 0 {
		h := sha256.New()
		return h.Sum(nil)
	}
	return subtreeHash(t.leaves)
}

// InclusionProof returns a proof that leaf index `idx` (0-based) is part of
// the current tree. The returned slice is the sibling-hash path, ordered
// from leaf to root.
func (t *MerkleTree) InclusionProof(idx int) ([][]byte, error) {
	n := len(t.leaves)
	if idx < 0 || idx >= n {
		return nil, fmt.Errorf("InclusionProof: idx %d out of range [0,%d)", idx, n)
	}
	return inclusionPath(t.leaves, idx, 0), nil
}

// VerifyInclusion checks that `leaf` (a raw leaf hash) is at index `idx`
// in a tree of size `treeSize` whose root is `root`, given an inclusion
// proof produced by InclusionProof.
func VerifyInclusion(leaf []byte, idx, treeSize int, proof [][]byte, root []byte) error {
	if len(leaf) != HashSize {
		return errors.New("VerifyInclusion: bad leaf size")
	}
	if idx < 0 || idx >= treeSize {
		return fmt.Errorf("VerifyInclusion: idx %d out of range [0,%d)", idx, treeSize)
	}
	if len(root) != HashSize {
		return errors.New("VerifyInclusion: bad root size")
	}

	// Walk leaf → root, consuming one proof hash per layer until the
	// remaining subtree has size 1.
	cur := append([]byte(nil), leaf...)
	pos := idx
	size := treeSize
	pi := 0
	for size > 1 {
		k := largestPowerOfTwoLessThan(size)
		if pos < k {
			// `cur` is in the left subtree of size k. The sibling is the
			// right subtree of size (size - k). We only consume a proof
			// hash when the right subtree actually exists.
			if size-k > 0 {
				if pi >= len(proof) {
					return errors.New("VerifyInclusion: proof too short")
				}
				cur = NodeHash(cur, proof[pi])
				pi++
			}
			size = k
		} else {
			// `cur` is in the right subtree. The sibling is the left
			// subtree of size k, which always exists.
			if pi >= len(proof) {
				return errors.New("VerifyInclusion: proof too short")
			}
			cur = NodeHash(proof[pi], cur)
			pi++
			pos -= k
			size -= k
		}
	}
	if pi != len(proof) {
		return errors.New("VerifyInclusion: proof too long")
	}
	if !equal(cur, root) {
		return errors.New("VerifyInclusion: root mismatch")
	}
	return nil
}

// ConsistencyProof returns a proof that a tree of size m can be extended
// (without modification) into the current tree of size n >= m. Empty
// proof is valid iff m == n.
func (t *MerkleTree) ConsistencyProof(m int) ([][]byte, error) {
	n := len(t.leaves)
	if m < 0 || m > n {
		return nil, fmt.Errorf("ConsistencyProof: m=%d out of range [0,%d]", m, n)
	}
	if m == 0 || m == n {
		return nil, nil
	}
	return consistencyPath(t.leaves, m, 0, true), nil
}

// VerifyConsistency checks that `oldRoot` (the root of a tree of size m)
// is consistent with `newRoot` (the root of a tree of size n) given a
// consistency proof.
func VerifyConsistency(m, n int, oldRoot, newRoot []byte, proof [][]byte) error {
	if m < 0 || n < m {
		return fmt.Errorf("VerifyConsistency: bad sizes m=%d n=%d", m, n)
	}
	if m == n {
		if len(proof) != 0 {
			return errors.New("VerifyConsistency: proof must be empty when m == n")
		}
		if !equal(oldRoot, newRoot) {
			return errors.New("VerifyConsistency: oldRoot != newRoot for m == n")
		}
		return nil
	}
	if m == 0 {
		if len(proof) != 0 {
			return errors.New("VerifyConsistency: proof must be empty when m == 0")
		}
		return nil
	}

	// RFC 6962 §2.1.2: split the proof into the path from the old tree's
	// "border" leaf to the new root.
	node := m - 1
	lastNode := n - 1
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}

	pi := 0
	var fr, sr []byte
	if node > 0 {
		if pi >= len(proof) {
			return errors.New("VerifyConsistency: proof too short")
		}
		fr = proof[pi]
		sr = proof[pi]
		pi++
	} else {
		fr = oldRoot
		sr = oldRoot
	}

	for node > 0 {
		if node%2 == 1 {
			if pi >= len(proof) {
				return errors.New("VerifyConsistency: proof too short")
			}
			fr = NodeHash(proof[pi], fr)
			sr = NodeHash(proof[pi], sr)
			pi++
		} else if node < lastNode {
			if pi >= len(proof) {
				return errors.New("VerifyConsistency: proof too short")
			}
			sr = NodeHash(sr, proof[pi])
			pi++
		}
		node /= 2
		lastNode /= 2
	}

	for lastNode > 0 {
		if pi >= len(proof) {
			return errors.New("VerifyConsistency: proof too short")
		}
		sr = NodeHash(sr, proof[pi])
		pi++
		lastNode /= 2
	}

	if pi != len(proof) {
		return errors.New("VerifyConsistency: proof too long")
	}
	if !equal(fr, oldRoot) {
		return errors.New("VerifyConsistency: derived old root mismatch")
	}
	if !equal(sr, newRoot) {
		return errors.New("VerifyConsistency: derived new root mismatch")
	}
	return nil
}

// --- internal helpers ---

func subtreeHash(leaves [][]byte) []byte {
	n := len(leaves)
	switch n {
	case 0:
		panic("subtreeHash: empty subtree")
	case 1:
		return append([]byte(nil), leaves[0]...)
	}
	k := largestPowerOfTwoLessThan(n)
	return NodeHash(subtreeHash(leaves[:k]), subtreeHash(leaves[k:]))
}

func inclusionPath(leaves [][]byte, idx, depth int) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if idx < k {
		rest := inclusionPath(leaves[:k], idx, depth+1)
		// Append the sibling (the right subtree's hash) only when it
		// actually has leaves.
		if k < n {
			return append(rest, subtreeHash(leaves[k:]))
		}
		return rest
	}
	rest := inclusionPath(leaves[k:], idx-k, depth+1)
	return append(rest, subtreeHash(leaves[:k]))
}

func consistencyPath(leaves [][]byte, m, depth int, atRoot bool) [][]byte {
	n := len(leaves)
	if m == n {
		if atRoot {
			return nil
		}
		return [][]byte{subtreeHash(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		path := consistencyPath(leaves[:k], m, depth+1, atRoot)
		return append(path, subtreeHash(leaves[k:]))
	}
	path := consistencyPath(leaves[k:], m-k, depth+1, false)
	return append(path, subtreeHash(leaves[:k]))
}

func largestPowerOfTwoLessThan(n int) int {
	// Smallest power-of-two that is strictly less than n, when n > 1.
	// For n == 1 this is undefined; callers must avoid that path.
	if n < 2 {
		panic(fmt.Sprintf("largestPowerOfTwoLessThan: n=%d", n))
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
