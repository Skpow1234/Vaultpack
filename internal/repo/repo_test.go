package repo_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/repo"
	"github.com/Skpow1234/Vaultpack/pkg/vaultpack"
)

func ed25519PEMs(t *testing.T) (priv, pub []byte) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

func makeBundle(t *testing.T, dir, name, payload string) []byte {
	t.Helper()
	out := filepath.Join(dir, name)
	_, err := vaultpack.Protect(vaultpack.ProtectOptions{
		Plaintext:  []byte(payload),
		OutputPath: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRepoInit_OpenEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{Description: "test"}); err != nil {
		t.Fatal(err)
	}
	r, err := repo.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size() != 0 {
		t.Errorf("size = %d, want 0", r.Size())
	}
	if r.LastRoot() != nil {
		t.Error("LastRoot should be nil for empty repo")
	}
}

func TestRepoInit_RejectsTwice(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Init(dir, repo.InitOptions{}); err == nil {
		t.Fatal("expected second Init to refuse existing repo.json")
	}
}

func TestRepoAdd_AndVerify_Signed(t *testing.T) {
	dir := t.TempDir()
	priv, pub := ed25519PEMs(t)

	if err := repo.Init(dir, repo.InitOptions{
		Description:   "signed repo",
		SigningKeyPEM: priv,
	}); err != nil {
		t.Fatal(err)
	}

	r, err := repo.Open(dir, priv)
	if err != nil {
		t.Fatal(err)
	}

	bundleDir := t.TempDir()
	for i := 0; i < 5; i++ {
		bundleBytes := makeBundle(t, bundleDir, "b.vpack", "payload "+string(rune('a'+i)))
		res, err := r.Add(repo.AddOptions{BundleBytes: bundleBytes, BundleName: "b.vpack"})
		if err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
		if res.Entry.Seq != int64(i) {
			t.Errorf("Add %d: seq=%d", i, res.Entry.Seq)
		}
		if res.Root.SignatureB64 == "" {
			t.Errorf("Add %d: expected signed root", i)
		}
	}
	if r.Size() != 5 {
		t.Errorf("size = %d, want 5", r.Size())
	}

	// Re-open and verify.
	r2, err := repo.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Size() != 5 {
		t.Fatalf("reopened size = %d, want 5", r2.Size())
	}

	vr, err := r2.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("verify failed: %+v", vr)
	}
	if vr.NumEntries != 5 {
		t.Errorf("NumEntries = %d", vr.NumEntries)
	}
}

func TestRepoVerify_TamperedEntry(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := repo.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	bundleDir := t.TempDir()
	for i := 0; i < 3; i++ {
		b := makeBundle(t, bundleDir, "b.vpack", "x")
		if _, err := r.Add(repo.AddOptions{BundleBytes: b}); err != nil {
			t.Fatal(err)
		}
	}

	// Tamper entries.jsonl: flip a bit in line 2.
	entries := filepath.Join(dir, "entries.jsonl")
	raw, err := os.ReadFile(entries)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	// Replace one occurrence of "bundle_sha256":"..." with a bogus value.
	lines[1] = strings.Replace(lines[1], `"bundle_sha256":"`, `"bundle_sha256":"0`, 1)
	// That extra '0' makes it 65 chars; the decode will still succeed but the
	// recomputed leaf hash won't match, which is what we want to catch.
	if err := os.WriteFile(entries, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	r2, err := repo.Open(dir, nil)
	if err != nil {
		// Open may also catch the corruption; that's fine.
		return
	}
	vr, err := r2.Verify(nil)
	if err != nil {
		return
	}
	if vr.OK {
		t.Fatal("verify should have failed on tampered entry")
	}
}

func TestRepoOpen_WrongSigningKeyFails(t *testing.T) {
	dir := t.TempDir()
	priv1, _ := ed25519PEMs(t)
	priv2, _ := ed25519PEMs(t)
	if err := repo.Init(dir, repo.InitOptions{SigningKeyPEM: priv1}); err != nil {
		t.Fatal(err)
	}
	_, err := repo.Open(dir, priv2)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRepoList_Limit(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := repo.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	bdir := t.TempDir()
	for i := 0; i < 6; i++ {
		b := makeBundle(t, bdir, "b.vpack", "p")
		_, _ = r.Add(repo.AddOptions{BundleBytes: b})
	}
	entries, roots, err := r.List(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || len(roots) != 3 {
		t.Errorf("List(3) returned %d entries, %d roots", len(entries), len(roots))
	}
	if entries[0].Seq != 3 {
		t.Errorf("List(3)[0].Seq = %d, want 3", entries[0].Seq)
	}
}

func TestRepoAdd_StoreBundles(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{StoreBundles: true}); err != nil {
		t.Fatal(err)
	}
	r, _ := repo.Open(dir, nil)

	bundleBytes := makeBundle(t, t.TempDir(), "b.vpack", "store me")
	res, err := r.Add(repo.AddOptions{
		BundleBytes: bundleBytes,
		CopyBundle:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(dir, "bundles", res.Entry.BundleSHA256+".vpack")
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("stored bundle missing: %v", err)
	}
}

func TestRepoVerify_UnsignedRepo(t *testing.T) {
	dir := t.TempDir()
	if err := repo.Init(dir, repo.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	r, _ := repo.Open(dir, nil)
	bd := t.TempDir()
	for i := 0; i < 4; i++ {
		b := makeBundle(t, bd, "b.vpack", "x")
		_, _ = r.Add(repo.AddOptions{BundleBytes: b})
	}
	vr, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("unsigned verify should pass: %+v", vr)
	}
}
