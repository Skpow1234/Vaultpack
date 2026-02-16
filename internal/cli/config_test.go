package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/config"
)

func TestConfigCmd_LoadOrder(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".vpack.yaml")
	content := []byte("cipher: chacha20-poly1305\nchunk_size: 32768\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Load config as the CLI would (PersistentPreRun).
	_, err := config.Load(cfgPath, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	c := config.Get()
	if c == nil {
		t.Fatal("config.Get() is nil")
	}
	if c.Cipher != "chacha20-poly1305" {
		t.Errorf("cipher: got %q, want chacha20-poly1305", c.Cipher)
	}
	if c.ChunkSize != 32768 {
		t.Errorf("chunk_size: got %d, want 32768", c.ChunkSize)
	}
}

func TestConfigCmd_ProfileSelection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vpack.yaml")
	content := []byte(`audit_log: /default.jsonl
profiles:
  prod:
    audit_log: /var/log/prod.jsonl
`)
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, _ = config.Load(cfgPath, "prod")
	c := config.Get()
	if c == nil {
		t.Fatal("config.Get() is nil")
	}
	if c.AuditLog != "/var/log/prod.jsonl" {
		t.Errorf("prod audit_log: got %q, want /var/log/prod.jsonl", c.AuditLog)
	}

	_, _ = config.Load(cfgPath, "")
	c = config.Get()
	if c.AuditLog != "/default.jsonl" {
		t.Errorf("no profile audit_log: got %q, want /default.jsonl", c.AuditLog)
	}
}

func TestConfigCmd_EffectiveConfigJSON(t *testing.T) {
	config.SetLoaded(&config.EffectiveConfig{
		Cipher:    "xchacha20-poly1305",
		ChunkSize: 8192,
	})
	defer config.SetLoaded(nil)

	c := config.Get()
	if c == nil {
		t.Fatal("config is nil")
	}
	// Ensure EffectiveConfig is JSON-marshalable (used by config --json).
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal EffectiveConfig: %v", err)
	}
	var decoded config.EffectiveConfig
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Cipher != c.Cipher {
		t.Errorf("round-trip cipher: got %q", decoded.Cipher)
	}
}
