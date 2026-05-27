package repo

import (
	"bufio"
	"crypto/sha256"
	stdcrypto "crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// Repo is a handle to an on-disk tamper-evident repo.
type Repo struct {
	dir    string
	cfg    Config
	mu     sync.Mutex // serialises Add operations
	tree   *MerkleTree
	tail   *Root // last root, or nil if empty
	signer stdcrypto.Signer
	algo   string
}

// InitOptions controls Repo.Init.
type InitOptions struct {
	Description   string
	SigningKeyPEM []byte // optional; if empty, repo is unsigned (warning emitted by CLI)
	RekorURL      string
	StoreBundles  bool
}

// Init creates a new repo at dir. The directory must not already contain
// a repo.json (use Open to attach to an existing one).
func Init(dir string, opts InitOptions) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("repo init: mkdir: %w", err)
	}
	if _, err := os.Stat(filepath.Join(dir, configFile)); err == nil {
		return fmt.Errorf("repo init: %s already exists at %s", configFile, dir)
	}

	cfg := Config{
		Schema:       SchemaVersion,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Description:  opts.Description,
		RekorURL:     opts.RekorURL,
		StoreBundles: opts.StoreBundles,
	}
	if opts.SigningKeyPEM != nil {
		signer, algo, err := crypto.ParsePrivateKey(opts.SigningKeyPEM)
		if err != nil {
			return fmt.Errorf("repo init: parse signing key: %w", err)
		}
		fp, err := publicKeyFingerprint(signer)
		if err != nil {
			return fmt.Errorf("repo init: fingerprint: %w", err)
		}
		cfg.SigningKeyAlgo = algo
		cfg.SigningKeyFP = fp
	}

	// Write config and empty append-only files.
	if err := writeJSON(filepath.Join(dir, configFile), cfg); err != nil {
		return err
	}
	for _, name := range []string{entriesFile, rootsFile} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("repo init: create %s: %w", name, err)
		}
		f.Close()
	}
	if opts.StoreBundles {
		if err := os.MkdirAll(filepath.Join(dir, bundlesSubdir), 0o700); err != nil {
			return fmt.Errorf("repo init: bundles dir: %w", err)
		}
	}
	return nil
}

// Open attaches to an existing repo at dir, replaying entries.jsonl and
// roots.jsonl to rebuild the in-memory Merkle tree. If signingKeyPEM is
// non-nil it MUST match the fingerprint recorded in repo.json; use it
// when you intend to call Add (sign new roots).
func Open(dir string, signingKeyPEM []byte) (*Repo, error) {
	cfgBytes, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return nil, fmt.Errorf("repo open: read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("repo open: parse config: %w", err)
	}
	if cfg.Schema != SchemaVersion {
		return nil, fmt.Errorf("repo open: schema version %d (want %d)", cfg.Schema, SchemaVersion)
	}

	r := &Repo{dir: dir, cfg: cfg, tree: NewMerkleTree()}

	if signingKeyPEM != nil {
		signer, algo, err := crypto.ParsePrivateKey(signingKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("repo open: parse signing key: %w", err)
		}
		fp, err := publicKeyFingerprint(signer)
		if err != nil {
			return nil, fmt.Errorf("repo open: fingerprint: %w", err)
		}
		if cfg.SigningKeyFP != "" && fp != cfg.SigningKeyFP {
			return nil, fmt.Errorf("repo open: signing key fingerprint mismatch (want %s, got %s)", cfg.SigningKeyFP, fp)
		}
		r.signer = signer
		r.algo = algo
	}

	if err := r.replayEntries(); err != nil {
		return nil, err
	}
	if err := r.replayRoots(); err != nil {
		return nil, err
	}
	return r, nil
}

// Config returns a copy of the repo's configuration.
func (r *Repo) Config() Config { return r.cfg }

// Size returns the number of entries currently in the repo.
func (r *Repo) Size() int { return r.tree.Size() }

// LastRoot returns the most recent signed root, or nil if the repo is empty.
func (r *Repo) LastRoot() *Root {
	if r.tail == nil {
		return nil
	}
	out := *r.tail
	return &out
}

// Add appends a new bundle to the repo and returns the new entry + root.
// Add is safe for concurrent use, but only one Add can be in flight at a
// time (the function takes an exclusive lock).
func (r *Repo) Add(opts AddOptions) (*AddResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(opts.BundleBytes) == 0 {
		return nil, errors.New("repo add: BundleBytes is required")
	}

	// Validate the bundle by parsing its manifest. We don't decrypt or
	// verify signatures here — repo just records what was added; the
	// caller can run `vaultpack verify` separately if needed.
	br, err := bundle.ReadBytes(opts.BundleBytes)
	if err != nil {
		return nil, fmt.Errorf("repo add: parse bundle: %w", err)
	}

	// Compute the leaf data deterministically. We use the SHA-256 of the
	// .vpack bytes plus the next sequence number to make leaves unique
	// even if the exact same bundle is added twice.
	bundleHash := sha256.Sum256(opts.BundleBytes)
	bundleSHA256Hex := hex.EncodeToString(bundleHash[:])
	seq := int64(r.tree.Size())
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	leafData := canonicalLeafData(seq, ts, bundleHash[:])
	leafHash := LeafHash(leafData)
	newRoot, err := r.tree.AppendLeaf(leafHash)
	if err != nil {
		return nil, fmt.Errorf("repo add: tree append: %w", err)
	}

	entry := Entry{
		Seq:          seq,
		Timestamp:    ts,
		BundleName:   opts.BundleName,
		BundleSHA256: bundleSHA256Hex,
		BundleSize:   int64(len(opts.BundleBytes)),
		LeafHashHex:  hex.EncodeToString(leafHash),
	}
	if opts.EmbedManifest {
		entry.ManifestB64 = util.B64Encode(br.ManifestBytes)
	}

	prevRoot := ""
	if r.tail != nil {
		prevRoot = r.tail.RootHashHex
	}
	root := Root{
		Seq:         seq,
		Timestamp:   ts,
		TreeSize:    seq + 1,
		RootHashHex: hex.EncodeToString(newRoot),
		PrevRootHex: prevRoot,
	}

	// Decide which signing key to use: per-Add takes priority over the
	// repo-default loaded by Open.
	signer, algo, err := r.signerForAdd(opts)
	if err != nil {
		return nil, err
	}
	if signer != nil {
		sigMsg := canonicalRootMessage(&root)
		sig, err := crypto.SignMessage(signer, algo, sigMsg)
		if err != nil {
			return nil, fmt.Errorf("repo add: sign root: %w", err)
		}
		root.SigAlgo = algo
		root.SignatureB64 = util.B64Encode(sig)
	}

	// Append to disk: entries first, then root. If we crash between the
	// two, replayEntries will see an entry without a root and refuse to
	// open; the operator can either remove the dangling entry line or
	// run a recovery tool. (Documented in the design doc.)
	if err := appendJSONL(filepath.Join(r.dir, entriesFile), entry); err != nil {
		return nil, err
	}
	if err := appendJSONL(filepath.Join(r.dir, rootsFile), root); err != nil {
		return nil, err
	}

	// Optionally copy the bundle into bundles/.
	if opts.CopyBundle && r.cfg.StoreBundles {
		dst := filepath.Join(r.dir, bundlesSubdir, bundleSHA256Hex+".vpack")
		if err := os.WriteFile(dst, opts.BundleBytes, 0o600); err != nil {
			return nil, fmt.Errorf("repo add: copy bundle: %w", err)
		}
	}

	rootCopy := root
	r.tail = &rootCopy
	return &AddResult{Entry: entry, Root: root}, nil
}

// List returns all entries (paired with their root) in append order.
// Limit <= 0 returns everything.
func (r *Repo) List(limit int) ([]Entry, []Root, error) {
	entries, err := r.loadEntries()
	if err != nil {
		return nil, nil, err
	}
	roots, err := r.loadRoots()
	if err != nil {
		return nil, nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
		roots = roots[len(roots)-limit:]
	}
	return entries, roots, nil
}

// Verify walks the entire log forward, recomputing the Merkle root at
// each step and verifying every recorded root signature. Returns OK
// iff the chain is intact end-to-end.
func (r *Repo) Verify(verifierPEM []byte) (*VerifyResult, error) {
	entries, err := r.loadEntries()
	if err != nil {
		return nil, err
	}
	roots, err := r.loadRoots()
	if err != nil {
		return nil, err
	}
	if len(entries) != len(roots) {
		return &VerifyResult{
			OK:            false,
			NumEntries:    int64(len(entries)),
			NumRoots:      int64(len(roots)),
			BadEntryIndex: -1,
			Reason:        fmt.Sprintf("entry/root count mismatch: %d entries vs %d roots", len(entries), len(roots)),
			Checked:       time.Now().UTC(),
		}, nil
	}

	var verifier any
	if verifierPEM != nil {
		pub, _, err := crypto.ParseAnyPublicKey(verifierPEM)
		if err != nil {
			return nil, fmt.Errorf("repo verify: parse verifier key: %w", err)
		}
		verifier = pub
	}

	tree := NewMerkleTree()
	var lastRootHex string
	for i, e := range entries {
		root := roots[i]
		if root.Seq != e.Seq {
			return badResult(i, fmt.Sprintf("seq mismatch at index %d: entry.seq=%d root.seq=%d", i, e.Seq, root.Seq), len(entries), len(roots), lastRootHex)
		}

		leafHash, err := hex.DecodeString(e.LeafHashHex)
		if err != nil || len(leafHash) != HashSize {
			return badResult(i, fmt.Sprintf("entry %d: bad leaf_hash_hex", i), len(entries), len(roots), lastRootHex)
		}
		// Verify the leaf hash matches the canonical encoding of the
		// entry's bundle bits (catches tampering with bundle_sha256 or ts).
		bundleHash, err := hex.DecodeString(e.BundleSHA256)
		if err != nil || len(bundleHash) != sha256.Size {
			return badResult(i, fmt.Sprintf("entry %d: bad bundle_sha256", i), len(entries), len(roots), lastRootHex)
		}
		wantLeafHash := LeafHash(canonicalLeafData(e.Seq, e.Timestamp, bundleHash))
		if !equal(wantLeafHash, leafHash) {
			return badResult(i, fmt.Sprintf("entry %d: leaf hash mismatch", i), len(entries), len(roots), lastRootHex)
		}
		if _, err := tree.AppendLeaf(leafHash); err != nil {
			return nil, err
		}

		// Root must match.
		gotRoot := tree.Root()
		gotRootHex := hex.EncodeToString(gotRoot)
		if gotRootHex != root.RootHashHex {
			return badResult(i, fmt.Sprintf("entry %d: recomputed root != recorded root (%s vs %s)", i, gotRootHex, root.RootHashHex), len(entries), len(roots), lastRootHex)
		}
		// Chain link.
		if root.PrevRootHex != lastRootHex {
			return badResult(i, fmt.Sprintf("entry %d: prev_root chain broken (%s vs %s)", i, root.PrevRootHex, lastRootHex), len(entries), len(roots), lastRootHex)
		}

		// Signature, if any.
		if root.SignatureB64 != "" {
			if verifier == nil {
				return badResult(i, fmt.Sprintf("entry %d: root is signed but no verifier key supplied", i), len(entries), len(roots), lastRootHex)
			}
			sig, err := util.B64Decode(root.SignatureB64)
			if err != nil {
				return badResult(i, fmt.Sprintf("entry %d: bad signature_b64", i), len(entries), len(roots), lastRootHex)
			}
			ok, err := crypto.VerifySignature(verifier, root.SigAlgo, canonicalRootMessage(&root), sig)
			if err != nil || !ok {
				return badResult(i, fmt.Sprintf("entry %d: signature verification failed", i), len(entries), len(roots), lastRootHex)
			}
		}

		lastRootHex = root.RootHashHex
	}

	return &VerifyResult{
		OK:            true,
		NumEntries:    int64(len(entries)),
		NumRoots:      int64(len(roots)),
		BadEntryIndex: -1,
		FinalRootHex:  lastRootHex,
		Checked:       time.Now().UTC(),
	}, nil
}

// --- internal helpers ---

func badResult(i int, reason string, ne, nr int, lastRoot string) (*VerifyResult, error) {
	return &VerifyResult{
		OK:            false,
		NumEntries:    int64(ne),
		NumRoots:      int64(nr),
		BadEntryIndex: int64(i),
		Reason:        reason,
		FinalRootHex:  lastRoot,
		Checked:       time.Now().UTC(),
	}, nil
}

func (r *Repo) signerForAdd(opts AddOptions) (stdcrypto.Signer, string, error) {
	if opts.SigningKeyPEM != nil {
		signer, algo, err := crypto.ParsePrivateKey(opts.SigningKeyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("repo add: parse signing key: %w", err)
		}
		fp, err := publicKeyFingerprint(signer)
		if err != nil {
			return nil, "", err
		}
		if r.cfg.SigningKeyFP != "" && fp != r.cfg.SigningKeyFP {
			return nil, "", fmt.Errorf("repo add: signing key fingerprint %s does not match repo's %s", fp, r.cfg.SigningKeyFP)
		}
		return signer, algo, nil
	}
	return r.signer, r.algo, nil // may be (nil, "", nil) for an unsigned repo
}

func (r *Repo) replayEntries() error {
	entries, err := r.loadEntries()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Seq != int64(i) {
			return fmt.Errorf("repo open: entries.jsonl line %d has seq %d (want %d)", i, e.Seq, i)
		}
		leafHash, err := hex.DecodeString(e.LeafHashHex)
		if err != nil || len(leafHash) != HashSize {
			return fmt.Errorf("repo open: entries.jsonl line %d: bad leaf hash", i)
		}
		if _, err := r.tree.AppendLeaf(leafHash); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) replayRoots() error {
	roots, err := r.loadRoots()
	if err != nil {
		return err
	}
	if len(roots) > 0 {
		last := roots[len(roots)-1]
		r.tail = &last
	}
	if int(r.tree.Size()) != len(roots) {
		return fmt.Errorf("repo open: %d entries but %d roots", r.tree.Size(), len(roots))
	}
	return nil
}

func (r *Repo) loadEntries() ([]Entry, error) {
	return loadJSONL[Entry](filepath.Join(r.dir, entriesFile))
}

func (r *Repo) loadRoots() ([]Root, error) {
	return loadJSONL[Root](filepath.Join(r.dir, rootsFile))
}

func loadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // up to 16 MiB per line
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

func appendJSONL(path string, v any) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("append %s: %w", path, err)
	}
	defer f.Close()
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Sync()
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// canonicalLeafData is the deterministic byte string that gets hashed
// into a tree leaf. Any change here is a tree-format breaking change.
func canonicalLeafData(seq int64, ts string, bundleSHA []byte) []byte {
	// "vpack-leaf-v1\x00<seq>\x00<ts>\x00<bundle_sha256>"
	out := []byte("vpack-leaf-v1\x00")
	out = append(out, []byte(fmt.Sprintf("%d", seq))...)
	out = append(out, 0)
	out = append(out, []byte(ts)...)
	out = append(out, 0)
	out = append(out, bundleSHA...)
	return out
}

// canonicalRootMessage is the byte string signed by the repo's signing
// key for each new root.
func canonicalRootMessage(r *Root) []byte {
	out := []byte("vpack-root-v1\x00")
	out = append(out, []byte(fmt.Sprintf("%d", r.Seq))...)
	out = append(out, 0)
	out = append(out, []byte(r.Timestamp)...)
	out = append(out, 0)
	out = append(out, []byte(fmt.Sprintf("%d", r.TreeSize))...)
	out = append(out, 0)
	out = append(out, []byte(r.RootHashHex)...)
	out = append(out, 0)
	out = append(out, []byte(r.PrevRootHex)...)
	return out
}

// publicKeyFingerprint returns a stable, short hex digest of a public key.
func publicKeyFingerprint(signer stdcrypto.Signer) (string, error) {
	pemBytes, err := crypto.MarshalPublicKeyPEM(signer.Public())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pemBytes)
	return hex.EncodeToString(sum[:8]), nil
}

// Compile-time check: we use io.EOF in some paths. Keep the import alive
// without polluting handlers.
var _ = io.EOF
