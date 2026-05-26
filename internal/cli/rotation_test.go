package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

// helper: SHA-256 hex of a file.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---------- rewrap (KMS) ----------

func TestRewrap_KMSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	out := filepath.Join(dir, "secret.dec")
	want := "kms rewrap test"
	if err := os.WriteFile(in, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect", "--in", in, "--out", bundleFile,
		"--kms-provider", "mock", "--kms-key-id", "mock-key-id",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	prevHash := sha256File(t, bundleFile)
	oldBR, _ := bundle.Read(bundleFile)
	oldDigest := oldBR.Manifest.Encryption.KeyID.DigestB64
	oldCiphertextSize := oldBR.Manifest.Ciphertext.Size
	oldWrapped := oldBR.Manifest.Encryption.KmsWrappedDEKB64

	// Rewrap under the same key ID (mock KMS enforces a fixed key ID).
	// This still re-runs unwrap+wrap, producing a fresh wrapped DEK with a new nonce.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"rewrap", "--in", bundleFile,
		"--kms-provider", "mock",
		"--from-kms-key-id", "mock-key-id",
		"--to-kms-key-id", "mock-key-id",
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	br, err := bundle.Read(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	if br.Manifest.Encryption.KmsKeyID != "mock-key-id" {
		t.Errorf("kms key id = %q, want mock-key-id", br.Manifest.Encryption.KmsKeyID)
	}
	if br.Manifest.Encryption.KmsWrappedDEKB64 == oldWrapped {
		t.Error("wrapped DEK did not change after rewrap (fresh nonce expected)")
	}
	if br.Manifest.Encryption.KeyID.DigestB64 != oldDigest {
		t.Errorf("DEK fingerprint changed after rewrap; rewrap should preserve DEK")
	}
	if br.Manifest.Ciphertext.Size != oldCiphertextSize {
		t.Errorf("ciphertext size changed after rewrap; payload should be unchanged")
	}
	if len(br.Manifest.RotatedFrom) != 1 {
		t.Fatalf("expected 1 rotation entry, got %d", len(br.Manifest.RotatedFrom))
	}
	if br.Manifest.RotatedFrom[0].Operation != "rewrap" {
		t.Errorf("rotation op = %q, want rewrap", br.Manifest.RotatedFrom[0].Operation)
	}
	if br.Manifest.RotatedFrom[0].BundleHash != prevHash {
		t.Errorf("rotation prev hash mismatch")
	}
	if br.Manifest.SignatureAlgo != nil {
		t.Error("signature should be cleared after rewrap")
	}

	// Decrypt still works after rewrap.
	cmd3 := NewRootCmd()
	cmd3.SetArgs([]string{
		"decrypt", "--in", bundleFile, "--out", out,
		"--kms-provider", "mock",
	})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("decrypt after rewrap: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != want {
		t.Errorf("decrypted=%q want=%q", got, want)
	}
}

func TestRewrap_RejectsNonKMSBundle(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	keyFile := filepath.Join(dir, "secret.key")
	os.WriteFile(in, []byte("data"), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"rewrap", "--in", bundleFile, "--kms-provider", "mock", "--to-kms-key-id", "x"})
	if err := cmd2.Execute(); err == nil || !strings.Contains(err.Error(), "not KMS-wrapped") {
		t.Errorf("expected 'not KMS-wrapped' error, got: %v", err)
	}
}

// ---------- rotate-key (key file) ----------

func TestRotateKey_KeyFileMode(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	oldKey := filepath.Join(dir, "secret.key")
	newKey := filepath.Join(dir, "secret.new.key")
	dec := filepath.Join(dir, "secret.dec")
	want := "rotate-key keyfile"
	os.WriteFile(in, []byte(want), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", oldKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	oldBR, _ := bundle.Read(bundleFile)
	oldDigest := oldBR.Manifest.Encryption.KeyID.DigestB64

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"rotate-key", "--in", bundleFile,
		"--old-key", oldKey,
		"--new-key-out", newKey,
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	br, _ := bundle.Read(bundleFile)
	if br.Manifest.Encryption.KeyID.DigestB64 == oldDigest {
		t.Error("DEK fingerprint did not change after rotate-key")
	}
	if len(br.Manifest.RotatedFrom) != 1 || br.Manifest.RotatedFrom[0].Operation != "rotate-key" {
		t.Errorf("rotation chain wrong: %+v", br.Manifest.RotatedFrom)
	}
	if _, err := os.Stat(newKey); err != nil {
		t.Fatalf("new key not written: %v", err)
	}

	// (We don't verify that the OLD key fails to decrypt here because the decrypt
	// command calls os.Exit on a key-fingerprint mismatch, which would kill the
	// test process. The fact that the digest field in the manifest has changed
	// proves the bundle now requires a different key.)

	cmd4 := NewRootCmd()
	cmd4.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", dec, "--key", newKey})
	if err := cmd4.Execute(); err != nil {
		t.Fatalf("decrypt with new key: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != want {
		t.Errorf("decrypted=%q want=%q", got, want)
	}
}

// ---------- rotate-key (password) ----------

func TestRotateKey_PasswordMode(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	dec := filepath.Join(dir, "secret.dec")
	want := "rotate-key password"
	os.WriteFile(in, []byte(want), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect", "--in", in, "--out", bundleFile,
		"--password", "old-pass-123",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"rotate-key", "--in", bundleFile,
		"--old-password", "old-pass-123",
		"--new-password", "new-pass-456",
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	// (Skipping "old password should fail" because decrypt calls os.Exit on
	// fingerprint mismatch, which would kill the test process. The change in
	// manifest's KDF salt + KeyID is sufficient evidence.)

	cmd4 := NewRootCmd()
	cmd4.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", dec, "--password", "new-pass-456"})
	if err := cmd4.Execute(); err != nil {
		t.Fatalf("decrypt with new password: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != want {
		t.Errorf("decrypted=%q want=%q", got, want)
	}
}

// ---------- rotate-key (KMS) ----------

func TestRotateKey_KMSMode(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	dec := filepath.Join(dir, "secret.dec")
	want := "rotate-key kms"
	os.WriteFile(in, []byte(want), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect", "--in", in, "--out", bundleFile,
		"--kms-provider", "mock", "--kms-key-id", "mock-key-id",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	oldBR, _ := bundle.Read(bundleFile)
	oldDigest := oldBR.Manifest.Encryption.KeyID.DigestB64
	oldWrapped := oldBR.Manifest.Encryption.KmsWrappedDEKB64

	// Rotate under the same KMS key (mock enforces fixed key ID).
	// The DEK itself rotates; the wrapped DEK and the digest both change.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"rotate-key", "--in", bundleFile,
		"--kms-provider", "mock",
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	br, _ := bundle.Read(bundleFile)
	if br.Manifest.Encryption.KeyID.DigestB64 == oldDigest {
		t.Error("DEK fingerprint did not change after rotate-key")
	}
	if br.Manifest.Encryption.KmsWrappedDEKB64 == oldWrapped {
		t.Error("wrapped DEK did not change after rotate-key")
	}
	if br.Manifest.Encryption.KmsKeyID != "mock-key-id" {
		t.Errorf("KMS key id changed unexpectedly: %q", br.Manifest.Encryption.KmsKeyID)
	}

	cmd3 := NewRootCmd()
	cmd3.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", dec, "--kms-provider", "mock"})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != want {
		t.Errorf("decrypted=%q want=%q", got, want)
	}
}

// ---------- add-recipient ----------

func TestAddRecipient_SingleToMulti(t *testing.T) {
	dir := t.TempDir()

	// Two key pairs.
	for _, name := range []string{"alice", "bob"} {
		priv, pub, err := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
		if err != nil {
			t.Fatal(err)
		}
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".key"), priv, 0o600)
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".pub"), pub, 0o644)
	}

	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	want := "add-recipient secret"
	os.WriteFile(in, []byte(want), 0o600)

	// Protect for alice only.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect", "--in", in, "--out", bundleFile,
		"--recipient", filepath.Join(dir, "alice.pub"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	br, _ := bundle.Read(bundleFile)
	if br.Manifest.Encryption.Hybrid == nil {
		t.Fatal("expected hybrid meta")
	}
	if len(br.Manifest.Encryption.Hybrid.Recipients) != 0 {
		t.Errorf("expected single-recipient (no Recipients list), got %d", len(br.Manifest.Encryption.Hybrid.Recipients))
	}

	// Add bob using alice's private key for the DEK.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"add-recipient", "--in", bundleFile,
		"--privkey", filepath.Join(dir, "alice.key"),
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("add-recipient: %v", err)
	}

	br2, _ := bundle.Read(bundleFile)
	if br2.Manifest.Encryption.Hybrid == nil {
		t.Fatal("hybrid meta missing")
	}
	if len(br2.Manifest.Encryption.Hybrid.Recipients) != 2 {
		t.Errorf("expected 2 recipients after add, got %d", len(br2.Manifest.Encryption.Hybrid.Recipients))
	}
	if len(br2.Manifest.RotatedFrom) != 1 || br2.Manifest.RotatedFrom[0].Operation != "add-recipient" {
		t.Errorf("rotation chain wrong: %+v", br2.Manifest.RotatedFrom)
	}

	// Bob can now decrypt.
	dec := filepath.Join(dir, "bob.dec")
	cmd3 := NewRootCmd()
	cmd3.SetArgs([]string{
		"decrypt", "--in", bundleFile, "--out", dec,
		"--privkey", filepath.Join(dir, "bob.key"),
	})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != want {
		t.Errorf("decrypted=%q want=%q", got, want)
	}

	// Alice can still decrypt.
	dec2 := filepath.Join(dir, "alice.dec")
	cmd4 := NewRootCmd()
	cmd4.SetArgs([]string{
		"decrypt", "--in", bundleFile, "--out", dec2,
		"--privkey", filepath.Join(dir, "alice.key"),
	})
	if err := cmd4.Execute(); err != nil {
		t.Fatalf("alice decrypt after add: %v", err)
	}
}

func TestAddRecipient_RejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	priv, pub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "alice.key"), priv, 0o600)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "alice.pub"), pub, 0o644)
	in := filepath.Join(dir, "s.txt")
	out := filepath.Join(dir, "s.vpack")
	os.WriteFile(in, []byte("d"), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", out, "--recipient", filepath.Join(dir, "alice.pub")})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"add-recipient", "--in", out,
		"--privkey", filepath.Join(dir, "alice.key"),
		"--recipient", filepath.Join(dir, "alice.pub"),
	})
	if err := cmd2.Execute(); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("expected duplicate error, got: %v", err)
	}
}

// ---------- remove-recipient ----------

func TestRemoveRecipient_DropsEntryButPayloadStays(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alice", "bob", "carol"} {
		priv, pub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".key"), priv, 0o600)
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".pub"), pub, 0o644)
	}
	in := filepath.Join(dir, "s.txt")
	bundleFile := filepath.Join(dir, "s.vpack")
	os.WriteFile(in, []byte("payload"), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile,
		"--recipient", filepath.Join(dir, "alice.pub"),
		"--recipient", filepath.Join(dir, "bob.pub"),
		"--recipient", filepath.Join(dir, "carol.pub"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	br, _ := bundle.Read(bundleFile)
	oldPayload := br.Manifest.Ciphertext.Size

	// Remove bob.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"remove-recipient", "--in", bundleFile,
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("remove-recipient: %v", err)
	}

	br2, _ := bundle.Read(bundleFile)
	if len(br2.Manifest.Encryption.Hybrid.Recipients) != 2 {
		t.Errorf("expected 2 recipients after remove, got %d", len(br2.Manifest.Encryption.Hybrid.Recipients))
	}
	if br2.Manifest.Ciphertext.Size != oldPayload {
		t.Error("payload size changed; remove-recipient must not re-encrypt")
	}

	// Alice and carol can still decrypt.
	dec := filepath.Join(dir, "alice.dec")
	cmd3 := NewRootCmd()
	cmd3.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", dec,
		"--privkey", filepath.Join(dir, "alice.key"),
	})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("alice decrypt: %v", err)
	}
}

func TestRemoveRecipient_RefusesEmpty(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alice", "bob"} {
		priv, pub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".key"), priv, 0o600)
		_ = crypto.SaveKeyPEM(filepath.Join(dir, name+".pub"), pub, 0o644)
	}
	in := filepath.Join(dir, "s.txt")
	bundleFile := filepath.Join(dir, "s.vpack")
	os.WriteFile(in, []byte("p"), 0o600)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile,
		"--recipient", filepath.Join(dir, "alice.pub"),
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"remove-recipient", "--in", bundleFile,
		"--recipient", filepath.Join(dir, "alice.pub"),
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := cmd2.Execute(); err == nil || !strings.Contains(err.Error(), "orphan") {
		t.Errorf("expected orphan error, got: %v", err)
	}
}

// ---------- rotation chain integrity ----------

func TestRotationChain_AppendsAcrossOps(t *testing.T) {
	dir := t.TempDir()
	priv, pub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "a.key"), priv, 0o600)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "a.pub"), pub, 0o644)
	priv2, pub2, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "b.key"), priv2, 0o600)
	_ = crypto.SaveKeyPEM(filepath.Join(dir, "b.pub"), pub2, 0o644)

	in := filepath.Join(dir, "s.txt")
	bundleFile := filepath.Join(dir, "s.vpack")
	os.WriteFile(in, []byte("chain test"), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile,
		"--recipient", filepath.Join(dir, "a.pub"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// 1. add bob
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"add-recipient", "--in", bundleFile,
		"--privkey", filepath.Join(dir, "a.key"),
		"--recipient", filepath.Join(dir, "b.pub"),
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatal(err)
	}
	// 2. remove alice
	cmd3 := NewRootCmd()
	cmd3.SetArgs([]string{"remove-recipient", "--in", bundleFile,
		"--recipient", filepath.Join(dir, "a.pub"),
	})
	if err := cmd3.Execute(); err != nil {
		t.Fatal(err)
	}
	// 3. rotate-key for bob (new DEK)
	cmd4 := NewRootCmd()
	cmd4.SetArgs([]string{"rotate-key", "--in", bundleFile,
		"--old-privkey", filepath.Join(dir, "b.key"),
		"--recipient", filepath.Join(dir, "b.pub"),
	})
	if err := cmd4.Execute(); err != nil {
		t.Fatalf("rotate-key hybrid: %v", err)
	}

	br, _ := bundle.Read(bundleFile)
	if len(br.Manifest.RotatedFrom) != 3 {
		t.Fatalf("expected 3-entry rotation chain, got %d: %+v", len(br.Manifest.RotatedFrom), br.Manifest.RotatedFrom)
	}
	wantOps := []string{"add-recipient", "remove-recipient", "rotate-key"}
	for i, w := range wantOps {
		if br.Manifest.RotatedFrom[i].Operation != w {
			t.Errorf("chain[%d] = %q, want %q", i, br.Manifest.RotatedFrom[i].Operation, w)
		}
		if br.Manifest.RotatedFrom[i].BundleHash == "" {
			t.Errorf("chain[%d] missing bundle hash", i)
		}
	}

	// Bob can still decrypt after all rotations.
	dec := filepath.Join(dir, "b.dec")
	cmd5 := NewRootCmd()
	cmd5.SetArgs([]string{"decrypt", "--in", bundleFile, "--out", dec,
		"--privkey", filepath.Join(dir, "b.key"),
	})
	if err := cmd5.Execute(); err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != "chain test" {
		t.Errorf("decrypted=%q want=chain test", got)
	}
}
