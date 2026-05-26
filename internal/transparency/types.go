// Package transparency implements VaultPack's Sigstore integration:
//
//   - Rekor client for uploading hashedrekord entries and fetching SETs.
//   - Canonical body reconstruction + SET (Signed Entry Timestamp) verification.
//   - Fulcio client for keyless signing (OIDC → short-lived cert).
//
// The package is dependency-light by design: it speaks the documented JSON
// API of Rekor and Fulcio over net/http rather than pulling the full
// sigstore/rekor generated client into the dependency graph.
package transparency

const (
	// DefaultRekorURL is the public Rekor instance run by the Sigstore project.
	DefaultRekorURL = "https://rekor.sigstore.dev"
	// DefaultFulcioURL is the public Fulcio CA run by the Sigstore project.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
	// DefaultOIDCIssuer is the default OIDC issuer for keyless signing.
	DefaultOIDCIssuer = "https://oauth2.sigstore.dev/auth"

	// HashedRekord is Rekor's most common entry type: signature + pubkey + data hash.
	KindHashedRekord = "hashedrekord"
	// APIVersionV001 is the only spec version currently supported.
	APIVersionV001 = "0.0.1"
)

// HashedRekordEntry is the request/response body used to create or fetch a
// hashedrekord entry. The structure mirrors Rekor's published JSON schema.
type HashedRekordEntry struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Spec       HashedRekordEntrySpec `json:"spec"`
}

type HashedRekordEntrySpec struct {
	Signature HashedRekordSignature `json:"signature"`
	Data      HashedRekordData      `json:"data"`
}

type HashedRekordSignature struct {
	Content   string                `json:"content"` // base64(signature bytes)
	PublicKey HashedRekordPublicKey `json:"publicKey"`
}

type HashedRekordPublicKey struct {
	Content string `json:"content"` // base64(PEM-encoded public key OR PEM cert chain)
}

type HashedRekordData struct {
	Hash HashedRekordHash `json:"hash"`
}

type HashedRekordHash struct {
	Algorithm string `json:"algorithm"` // "sha256"
	Value     string `json:"value"`     // lowercase hex
}

// LogEntryAnon mirrors Rekor's models.LogEntryAnon: the per-UUID payload that
// Rekor returns from POST / GET. Maps keyed by UUID at the top level are
// represented as map[string]LogEntryAnon.
type LogEntryAnon struct {
	Body           string             `json:"body"`            // base64(canonical entry JSON)
	IntegratedTime int64              `json:"integratedTime"`
	LogID          string             `json:"logID"`           // hex(sha256(log_pub_DER))
	LogIndex       int64              `json:"logIndex"`
	Verification   *LogEntryVerifData `json:"verification,omitempty"`
}

// LogEntryVerifData carries Rekor's inclusion proof and SET. We only require
// the SET; the inclusion proof is structurally retained for forward-compat.
type LogEntryVerifData struct {
	SignedEntryTimestamp string             `json:"signedEntryTimestamp"`
	InclusionProof       *InclusionProof    `json:"inclusionProof,omitempty"`
}

type InclusionProof struct {
	LogIndex int64    `json:"logIndex"`
	RootHash string   `json:"rootHash"`
	TreeSize int64    `json:"treeSize"`
	Hashes   []string `json:"hashes"`
}
