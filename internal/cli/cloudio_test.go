package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsRemoteURI(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"az://c/b", true},
		{"s3://b/k", true},
		{"gs://b/k", true},
		{"https://example.com/f", true},
		{"http://example.com/f", true},
		{"./local", false},
		{"/abs/path", false},
		{"file.vpack", false},
	}
	for _, c := range cases {
		if got := isRemoteURI(c.in); got != c.want {
			t.Errorf("isRemoteURI(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCloudFlags_Registered(t *testing.T) {
	cmd := NewRootCmd()
	for _, name := range []string{"aws-region", "aws-profile", "s3-endpoint", "s3-path-style"} {
		if cmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("--%s flag not registered", name)
		}
	}
}

// End-to-end: round-trip a bundle locally, then serve it over HTTPS and
// confirm `inspect --in https://...` works.
func TestInspectCmd_HTTPSInput(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	bundleFile := filepath.Join(tmpDir, "test.vpack")
	keyFile := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(inputFile, []byte("hello https"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", inputFile, "--out", bundleFile, "--key-out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Serve the bundle file over HTTP.
	data, err := os.ReadFile(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"inspect", "--in", srv.URL + "/test.vpack"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("inspect over http failed: %v", err)
	}
}

// Decrypt also needs to handle https:// inputs (it just downloads to temp).
func TestDecryptCmd_HTTPSInput(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "secret.txt")
	bundleFile := filepath.Join(tmpDir, "secret.vpack")
	keyFile := filepath.Join(tmpDir, "secret.key")
	outFile := filepath.Join(tmpDir, "decrypted.txt")
	want := "this is the plaintext"
	if err := os.WriteFile(inputFile, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", inputFile, "--out", bundleFile, "--key-out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}
	data, err := os.ReadFile(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"decrypt", "--in", srv.URL + "/secret.vpack", "--out", outFile, "--key", keyFile})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("decrypted = %q, want %q", got, want)
	}
}

// HTTPS is read-only: writing to https:// must fail with a clear error.
func TestProtectCmd_HTTPSOutputRejected(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "in.txt")
	if err := os.WriteFile(inputFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", inputFile, "--out", "https://example.com/out.vpack"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when writing to https://")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("error should mention read-only, got: %v", err)
	}
}

// s3:// without AWS config should produce an AWS-related error.
func TestProtectCmd_S3InputWithoutConfig(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "out.vpack")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect",
		"--in", "s3://nonexistent-bucket-vpack-test/missing.txt",
		"--out", outFile,
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for s3:// without proper config or with missing object")
	}
}

// gs:// without GCS config should produce a GCS-related error.
func TestProtectCmd_GCSInputWithoutConfig(t *testing.T) {
	// Force a clean ADC state for this test.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/creds.json")
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "out.vpack")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect",
		"--in", "gs://nonexistent-bucket-vpack-test/missing.txt",
		"--out", outFile,
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for gs:// without proper config")
	}
}
