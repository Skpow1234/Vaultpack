package audit

import (
	"encoding/json"
	"testing"
)

func TestBuildProvenance_MarshalProvenance(t *testing.T) {
	p := BuildProvenance(
		"bundle.vpack",
		"deadbeef",
		"input.csv",
		100,
		"sha256",
		"abc123",
	)
	if p.SchemaVersion != "v1" {
		t.Errorf("schema_version = %q", p.SchemaVersion)
	}
	if p.Subject.BundlePath != "bundle.vpack" {
		t.Errorf("subject.bundle_path = %q", p.Subject.BundlePath)
	}
	if p.Subject.Digest != "sha256:deadbeef" {
		t.Errorf("subject.digest = %q", p.Subject.Digest)
	}
	if p.Subject.PlaintextHash != "sha256:abc123" {
		t.Errorf("subject.plaintext_hash = %q", p.Subject.PlaintextHash)
	}
	if p.Builder.ID != "vaultpack" {
		t.Errorf("builder.id = %q", p.Builder.ID)
	}
	raw, err := MarshalProvenance(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Provenance
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Subject.Digest != p.Subject.Digest {
		t.Error("round-trip digest mismatch")
	}
}
