package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEffective(t *testing.T) {
	d := DefaultEffective()
	if d.Cipher != "aes-256-gcm" {
		t.Errorf("default cipher: got %q, want aes-256-gcm", d.Cipher)
	}
	if d.ChunkSize != 65536 {
		t.Errorf("default chunk_size: got %d, want 65536", d.ChunkSize)
	}
	if d.OutputDir != "." {
		t.Errorf("default output_dir: got %q, want .", d.OutputDir)
	}
}

func TestLoad_NoFile(t *testing.T) {
	SetLoaded(nil)
	cfg, err := Load("", "")
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.Cipher != "aes-256-gcm" {
		t.Errorf("cipher: got %q, want default", cfg.Cipher)
	}
}

func TestLoad_ExplicitPath_NotFound(t *testing.T) {
	SetLoaded(nil)
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"), "")
	if err != nil {
		t.Fatalf("Load(nonexistent): %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}
	if cfg.Cipher != "aes-256-gcm" {
		t.Errorf("cipher: got %q, want default", cfg.Cipher)
	}
}

func TestLoad_ExplicitPath_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpack.yaml")
	content := []byte(`audit_log: /var/log/vpack.jsonl
cipher: chacha20-poly1305
chunk_size: 131072
output_dir: /tmp/out
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	SetLoaded(nil)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.AuditLog != "/var/log/vpack.jsonl" {
		t.Errorf("audit_log: got %q", cfg.AuditLog)
	}
	if cfg.Cipher != "chacha20-poly1305" {
		t.Errorf("cipher: got %q", cfg.Cipher)
	}
	if cfg.ChunkSize != 131072 {
		t.Errorf("chunk_size: got %d", cfg.ChunkSize)
	}
	if cfg.OutputDir != "/tmp/out" {
		t.Errorf("output_dir: got %q", cfg.OutputDir)
	}
}

func TestLoad_ProfileOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpack.yaml")
	content := []byte(`audit_log: /var/log/default.jsonl
cipher: aes-256-gcm
profiles:
  prod:
    audit_log: /var/log/vpack-prod.jsonl
    cipher: xchacha20-poly1305
  dev:
    output_dir: ./dev-out
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	SetLoaded(nil)
	cfg, err := Load(path, "prod")
	if err != nil {
		t.Fatalf("Load(prod): %v", err)
	}
	if cfg.AuditLog != "/var/log/vpack-prod.jsonl" {
		t.Errorf("prod audit_log: got %q", cfg.AuditLog)
	}
	if cfg.Cipher != "xchacha20-poly1305" {
		t.Errorf("prod cipher: got %q", cfg.Cipher)
	}

	SetLoaded(nil)
	cfg, err = Load(path, "dev")
	if err != nil {
		t.Fatalf("Load(dev): %v", err)
	}
	if cfg.OutputDir != "./dev-out" {
		t.Errorf("dev output_dir: got %q", cfg.OutputDir)
	}
	if cfg.AuditLog != "/var/log/default.jsonl" {
		t.Errorf("dev audit_log (inherit): got %q", cfg.AuditLog)
	}
}

func TestGet_SetLoaded(t *testing.T) {
	SetLoaded(nil)
	if Get() != nil {
		t.Error("Get() should be nil after SetLoaded(nil)")
	}
	c := &EffectiveConfig{Cipher: "test"}
	SetLoaded(c)
	if Get() != c {
		t.Error("Get() should return set config")
	}
	SetLoaded(nil)
}
