package bundle

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// zipNewWriter wraps zip.NewWriter to keep the test file clean.
func zipNewWriter(f *os.File) *zip.Writer {
	return zip.NewWriter(f)
}

func validManifest() *Manifest {
	return &Manifest{
		Version:   ManifestVersion,
		CreatedAt: "2026-02-11T10:00:00Z",
		Input: InputMeta{
			Name: "config.json",
			Size: 100,
		},
		Plaintext: PlaintextHash{
			Algo:      "sha256",
			DigestB64: util.B64Encode(make([]byte, 32)),
		},
		Encryption: EncryptionMeta{
			AEAD:     "aes-256-gcm",
			NonceB64: util.B64Encode(make([]byte, 12)),
			TagB64:   util.B64Encode(make([]byte, 16)),
			AADB64:   nil,
			KeyID: KeyID{
				Algo:      "sha256",
				DigestB64: util.B64Encode(make([]byte, 32)),
			},
		},
		Ciphertext: CiphertextMeta{
			Size: 116,
		},
	}
}

func TestBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.vpack")

	m := validManifest()
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ciphertext := []byte("encrypted-data-here")

	// Write bundle.
	err = Write(&WriteParams{
		OutputPath:    bundlePath,
		Ciphertext:    ciphertext,
		ManifestBytes: manifestBytes,
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	// Read bundle.
	result, err := Read(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	if string(result.Ciphertext) != string(ciphertext) {
		t.Error("ciphertext mismatch")
	}
	if result.Manifest.Version != ManifestVersion {
		t.Errorf("version: got %q, want %q", result.Manifest.Version, ManifestVersion)
	}
	if result.Manifest.Input.Name != "config.json" {
		t.Errorf("input name: got %q", result.Manifest.Input.Name)
	}
	if result.Signature != nil {
		t.Error("expected nil signature for unsigned bundle")
	}
}

func TestBundleWithSignature(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "signed.vpack")

	m := validManifest()
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sig := []byte("fake-signature")
	err = Write(&WriteParams{
		OutputPath:    bundlePath,
		Ciphertext:    []byte("data"),
		ManifestBytes: manifestBytes,
		Signature:     sig,
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := Read(bundlePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(result.Signature) != string(sig) {
		t.Error("signature mismatch")
	}
}

func TestReadMissingPayload(t *testing.T) {
	// Create a ZIP with only manifest.json, no payload.bin.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bad.vpack")

	m := validManifest()
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}

	// Write a zip manually with only manifest.
	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zipNewWriter(f)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(manifestBytes); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()

	_, err = Read(bundlePath)
	if err == nil {
		t.Fatal("expected error for missing payload")
	}
}

func TestReadManifestOnly(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.vpack")

	m := validManifest()
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}

	err = Write(&WriteParams{
		OutputPath:    bundlePath,
		Ciphertext:    []byte("data"),
		ManifestBytes: manifestBytes,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, rawBytes, err := ReadManifestOnly(bundlePath)
	if err != nil {
		t.Fatalf("ReadManifestOnly: %v", err)
	}
	if got.Version != ManifestVersion {
		t.Errorf("version mismatch")
	}
	if len(rawBytes) == 0 {
		t.Error("expected non-empty raw bytes")
	}
}

func TestManifestGolden(t *testing.T) {
	m := validManifest()
	data, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}

	// Verify key fields exist.
	if parsed["version"] != ManifestVersion {
		t.Errorf("version field: %v", parsed["version"])
	}
}

func TestCanonicalManifest_Deterministic(t *testing.T) {
	m := validManifest()
	c1, err := CanonicalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := CanonicalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Error("canonical output is not deterministic")
	}
}
