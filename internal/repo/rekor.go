package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/transparency"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

const defaultRekorTimeout = 30 * time.Second

// AnchorOptions configures Repo.Anchor.
type AnchorOptions struct {
	RekorURL      string // empty -> use repo.cfg.RekorURL
	SigningKeyPEM []byte // PEM private key; must match repo's signing key
	Seq           int64  // root sequence number to anchor; <0 means "latest"
}

// Anchor uploads a signed root to the Sigstore Rekor transparency log
// and (on success) rewrites roots.jsonl with the Rekor proof fields
// populated. This is a destructive append-style update — the existing
// root line is replaced in place (same Seq, same hashes), so the
// Merkle chain is preserved.
func (r *Repo) Anchor(opts AnchorOptions) (*Root, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rekorURL := opts.RekorURL
	if rekorURL == "" {
		rekorURL = r.cfg.RekorURL
	}
	if rekorURL == "" {
		return nil, fmt.Errorf("repo anchor: no Rekor URL configured (pass --rekor-url or set it at init)")
	}
	if opts.SigningKeyPEM == nil {
		return nil, fmt.Errorf("repo anchor: SigningKeyPEM is required")
	}

	roots, err := r.loadRoots()
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("repo anchor: repo is empty")
	}
	target := opts.Seq
	if target < 0 {
		target = roots[len(roots)-1].Seq
	}
	idx := -1
	for i, rt := range roots {
		if rt.Seq == target {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("repo anchor: seq %d not found", target)
	}
	root := roots[idx]
	if root.SignatureB64 == "" {
		return nil, fmt.Errorf("repo anchor: root %d has no signature; cannot upload to Rekor", target)
	}

	signer, _, err := crypto.ParsePrivateKey(opts.SigningKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("repo anchor: parse signing key: %w", err)
	}
	pubPEM, err := crypto.MarshalPublicKeyPEM(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("repo anchor: marshal pubkey: %w", err)
	}
	sigBytes, err := util.B64Decode(root.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("repo anchor: decode signature: %w", err)
	}

	// The Rekor hashedrekord entry binds (sha256(message), signature, pubkey).
	// For repo roots, the "message" is the canonical root encoding —
	// the same bytes that were signed when Add was called.
	msg := canonicalRootMessage(&root)

	client := transparency.NewRekorClient(rekorURL)
	entry := transparency.BuildHashedRekord(pubPEM, sigBytes, msg)
	ctx, cancel := context.WithTimeout(context.Background(), defaultRekorTimeout)
	defer cancel()
	uuid, anon, err := client.Upload(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("repo anchor: upload: %w", err)
	}

	root.RekorUUID = uuid
	root.RekorLogURL = rekorURL
	root.RekorLogIndex = anon.LogIndex
	_ = util.B64Encode // silence unused-import guard in case the rest is trimmed

	// Rewrite roots.jsonl with this root updated.
	roots[idx] = root
	if err := rewriteJSONL(r.dir, rootsFile, roots); err != nil {
		return nil, err
	}
	if r.tail != nil && r.tail.Seq == root.Seq {
		c := root
		r.tail = &c
	}
	return &root, nil
}

// rewriteJSONL atomically rewrites a JSONL file by writing to a temp file
// and renaming. Used by Anchor to update a single root line in place.
func rewriteJSONL[T any](dir, name string, rows []T) error {
	// Imports kept local for clarity.
	return rewriteRows(dir, name, rows)
}
