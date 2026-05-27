package repo

import "time"

// SchemaVersion is the on-disk schema for a `vaultpack repo` directory.
// Bumped only when a backwards-incompatible field is added; readers may
// continue to handle older schemas indefinitely.
const SchemaVersion = 1

// repoConfigFile, entriesFile, rootsFile, bundlesDir are the standard
// layout for a repo directory.
const (
	configFile    = "repo.json"
	entriesFile   = "entries.jsonl"
	rootsFile     = "roots.jsonl"
	bundlesSubdir = "bundles"
)

// Config is the marshalled repo.json document.
type Config struct {
	Schema          int    `json:"schema"`
	CreatedAt       string `json:"created_at"`
	Description     string `json:"description,omitempty"`
	SigningKeyAlgo  string `json:"signing_key_algo,omitempty"`
	SigningKeyFP    string `json:"signing_key_fingerprint,omitempty"`
	RekorURL        string `json:"rekor_url,omitempty"`
	StoreBundles    bool   `json:"store_bundles"`
}

// Entry is a single appended bundle's record, persisted one-per-line in
// entries.jsonl. Every entry is the leaf of the tree at index `Seq` and
// contributes to the root recorded in roots.jsonl at the same Seq.
type Entry struct {
	Seq          int64  `json:"seq"`
	Timestamp    string `json:"ts"`
	BundleName   string `json:"bundle_name,omitempty"`
	BundleSHA256 string `json:"bundle_sha256"`
	BundleSize   int64  `json:"bundle_size"`
	ManifestB64  string `json:"manifest_b64,omitempty"`
	LeafHashHex  string `json:"leaf_hash_hex"`
}

// Root is one signed-root record persisted in roots.jsonl. The root is
// taken over the tree of size Seq+1 (because Seq is 0-indexed).
type Root struct {
	Seq          int64  `json:"seq"`
	Timestamp    string `json:"ts"`
	TreeSize     int64  `json:"tree_size"`
	RootHashHex  string `json:"root_hash_hex"`
	PrevRootHex  string `json:"prev_root_hex,omitempty"`
	SigAlgo      string `json:"sig_algo,omitempty"`
	SignatureB64 string `json:"signature_b64,omitempty"`

	// Optional Sigstore Rekor inclusion proof for the root hash. Populated
	// when the repo is configured with --rekor-url.
	RekorUUID     string `json:"rekor_uuid,omitempty"`
	RekorLogURL   string `json:"rekor_log_url,omitempty"`
	RekorLogIndex int64  `json:"rekor_log_index,omitempty"`
}

// AddOptions controls a single Add operation.
type AddOptions struct {
	// BundleBytes is the .vpack file as raw bytes.
	BundleBytes []byte

	// BundleName is the friendly filename recorded in the entry; if empty
	// we use sha256 prefix.
	BundleName string

	// EmbedManifest, when true, base64-stores the manifest JSON in the
	// entry. Useful for offline `list` / `verify` without keeping the
	// .vpack around. False by default to keep entries.jsonl small.
	EmbedManifest bool

	// CopyBundle, when true, also writes the .vpack into bundles/<sha>.vpack.
	// Only honored when the repo was opened with StoreBundles=true.
	CopyBundle bool

	// SigningKey is a PEM-encoded private key used to sign the new root.
	// If empty, the repo's configured signing key (loaded via Open's
	// callback) is used.
	SigningKeyPEM []byte
}

// AddResult is returned by Repo.Add.
type AddResult struct {
	Entry Entry
	Root  Root
}

// VerifyResult is returned by Repo.Verify.
type VerifyResult struct {
	OK            bool
	NumEntries    int64
	NumRoots      int64
	BadEntryIndex int64  // -1 if all OK
	Reason        string // empty if OK
	FinalRootHex  string
	Checked       time.Time
}
