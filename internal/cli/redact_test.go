package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func TestRedact_OmitsSensitiveFields(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	m, _, err := bundle.ReadManifestOnly(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	r := Redact(m)

	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	forbidden := []string{
		"digest_b64",
		"nonce_b64",
		"tag_b64",
		"aad_b64",
		"salt_b64",
		"fingerprint_b64",
		"wrapped_dek_b64",
		"ephemeral_public_key_b64",
		"key_id",
	}
	for _, k := range forbidden {
		if bytes.Contains(out, []byte(k)) {
			t.Errorf("redacted JSON contains forbidden key %q:\n%s", k, out)
		}
	}

	// Sanity: it should still contain at least these safe fields.
	for _, k := range []string{"version", "input", "plaintext_hash", "encryption", "ciphertext"} {
		if !bytes.Contains(out, []byte(`"`+k+`"`)) {
			t.Errorf("redacted JSON missing expected field %q:\n%s", k, out)
		}
	}
}

func TestInspect_RedactFlag(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	root := NewRootCmd()
	root.SetArgs([]string{"inspect", "--in", bundlePath, "--redact", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect --redact: %v", err)
	}
}

func TestBatchInspect_RedactFlag(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "bundles")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a couple of bundles in the dir.
	for i := 0; i < 2; i++ {
		in := filepath.Join(subDir, "in.txt")
		out := filepath.Join(subDir, "b.vpack")
		key := filepath.Join(subDir, "b.key")
		os.WriteFile(in, []byte("data"), 0o600)
		r := NewRootCmd()
		r.SetArgs([]string{"protect", "--in", in, "--out", out, "--key-out", key})
		if err := r.Execute(); err != nil {
			t.Fatalf("protect: %v", err)
		}
	}

	root := NewRootCmd()
	root.SetArgs([]string{"batch-inspect", "--dir", subDir, "--redact", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-inspect --redact: %v", err)
	}
}
