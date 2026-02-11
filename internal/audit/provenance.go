package audit

import (
	"encoding/json"
	"runtime"
	"time"

	"os"
)

// Provenance is a SLSA-style provenance statement for a .vpack bundle.
type Provenance struct {
	SchemaVersion string            `json:"schema_version"` // e.g. "v1"
	Subject       ProvenanceSubject `json:"subject"`
	Builder       ProvenanceBuilder `json:"builder"`
	BuildTimestamp string          `json:"build_timestamp"` // RFC3339
	Environment   map[string]string `json:"environment,omitempty"`
}

type ProvenanceSubject struct {
	BundlePath string `json:"bundle_path"`
	Digest     string `json:"digest"`     // e.g. "sha256:hex..."
	InputName  string `json:"input_name,omitempty"`
	InputSize  int64  `json:"input_size,omitempty"`
	PlaintextHash string `json:"plaintext_hash,omitempty"` // algo:digest from manifest
}

type ProvenanceBuilder struct {
	ID   string `json:"id"`   // e.g. "vaultpack"
	Name string `json:"name"`  // e.g. "VaultPack CLI"
}

// BuildProvenance creates a provenance statement for a bundle using manifest metadata and optional bundle digest.
func BuildProvenance(bundlePath, bundleDigestHex, inputName string, inputSize int64, plaintextHashAlgo, plaintextHashB64 string) *Provenance {
	digest := bundleDigestHex
	if digest != "" && (len(digest) < 6 || digest[:6] != "sha256:") {
		digest = "sha256:" + digest
	}
	subject := ProvenanceSubject{
		BundlePath:     bundlePath,
		Digest:         digest,
		InputName:      inputName,
		InputSize:      inputSize,
		PlaintextHash:  "",
	}
	if plaintextHashAlgo != "" && plaintextHashB64 != "" {
		subject.PlaintextHash = plaintextHashAlgo + ":" + plaintextHashB64
	}
	hostname, _ := os.Hostname()
	env := map[string]string{
		"go_version": runtime.Version(),
		"go_os":      runtime.GOOS,
		"go_arch":    runtime.GOARCH,
		"hostname":   hostname,
	}
	return &Provenance{
		SchemaVersion:  "v1",
		Subject:        subject,
		Builder:        ProvenanceBuilder{ID: "vaultpack", Name: "VaultPack CLI"},
		BuildTimestamp: time.Now().UTC().Format(time.RFC3339),
		Environment:    env,
	}
}

// MarshalProvenance returns JSON bytes for the provenance statement.
func MarshalProvenance(p *Provenance) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}
