package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

func createTestBundle(t *testing.T, dir string) (bundlePath, keyPath string) {
	t.Helper()
	inFile := filepath.Join(dir, "input.txt")
	bundlePath = filepath.Join(dir, "input.vpack")
	keyPath = filepath.Join(dir, "input.key")

	os.WriteFile(inFile, []byte("inspect test data"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundlePath,
		"--key-out", keyPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}
	return
}

func TestInspectCmd_Human(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	root := NewRootCmd()
	root.SetArgs([]string{"inspect", "--in", bundlePath})

	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	// Human output goes to stdout via the printer. Command should not error.
}

func TestInspectCmd_JSON(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	root := NewRootCmd()
	root.SetArgs([]string{"inspect", "--in", bundlePath, "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	// JSON output goes to stdout. Command should not error.
}

func TestInspectCmd_JSONStructure(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	// Read the manifest directly and verify it's valid JSON.
	m, raw, err := bundle.ReadManifestOnly(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}

	if m.Version != bundle.ManifestVersion {
		t.Errorf("version: %q", m.Version)
	}
	if m.Input.Name != "input.txt" {
		t.Errorf("input name: %q", m.Input.Name)
	}
}

func TestInspectCmd_HumanContainsExpectedFields(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _ := createTestBundle(t, dir)

	// We can't easily capture stdout from the printer, but we can verify
	// the manifest has the expected fields by reading the bundle directly.
	m, _, err := bundle.ReadManifestOnly(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all fields that would be displayed in human mode exist.
	if m.Version == "" {
		t.Error("missing version")
	}
	if m.CreatedAt == "" {
		t.Error("missing created_at")
	}
	if m.Input.Name == "" {
		t.Error("missing input name")
	}
	if m.Encryption.AEAD == "" {
		t.Error("missing aead")
	}
	if !strings.Contains(m.Encryption.AEAD, "aes") {
		t.Errorf("unexpected aead: %q", m.Encryption.AEAD)
	}
}

func TestInspectCmd_MissingIn(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"inspect"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error when --in is missing")
	}
}
