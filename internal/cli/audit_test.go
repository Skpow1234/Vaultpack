package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttestCmd_OutputProvenance(t *testing.T) {
	// Create a minimal bundle (protect then attest).
	tmpDir := t.TempDir()
	in := filepath.Join(tmpDir, "in.txt")
	out := filepath.Join(tmpDir, "out.vpack")
	key := filepath.Join(tmpDir, "out.key")
	prov := filepath.Join(tmpDir, "provenance.json")
	if err := os.WriteFile(in, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd()
	root.SetArgs([]string{"protect", "--in", in, "--out", out, "--key-out", key})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	root2 := NewRootCmd()
	root2.SetArgs([]string{"attest", "--in", out, "--out", prov})
	if err := root2.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(prov)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		SchemaVersion string `json:"schema_version"`
		Subject       struct {
			BundlePath string `json:"bundle_path"`
			Digest     string `json:"digest"`
		} `json:"subject"`
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != "v1" {
		t.Errorf("schema_version = %q", p.SchemaVersion)
	}
	if p.Subject.BundlePath != out {
		t.Errorf("bundle_path = %q", p.Subject.BundlePath)
	}
	if p.Builder.ID != "vaultpack" {
		t.Errorf("builder.id = %q", p.Builder.ID)
	}
}

func TestSealCmd_VerifySealCmd_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	// Create two .vpack files via protect.
	for i, name := range []string{"a", "b"} {
		in := filepath.Join(tmpDir, name+".txt")
		out := filepath.Join(tmpDir, name+".vpack")
		if err := os.WriteFile(in, []byte("data"+string(rune('0'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
		root := NewRootCmd()
		root.SetArgs([]string{"protect", "--in", in, "--out", out, "--key-out", filepath.Join(tmpDir, name+".key")})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	rootFile := filepath.Join(tmpDir, "root.txt")
	root := NewRootCmd()
	root.SetArgs([]string{"seal", "--dir", tmpDir, "--out", rootFile})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	rootHex, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	rootStr := strings.TrimSpace(string(rootHex))
	root2 := NewRootCmd()
	root2.SetArgs([]string{"verify-seal", "--dir", tmpDir, "--root", rootStr})
	if err := root2.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportCmd(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	// One JSON line.
	if err := os.WriteFile(logPath, []byte(`{"timestamp":"2026-01-01T00:00:00Z","operation":"protect","input_file":"a","output_file":"b","success":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd()
	root.SetArgs([]string{"audit", "export", "--log", logPath, "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}
