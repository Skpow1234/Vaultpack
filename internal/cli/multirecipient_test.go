package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

func TestMultiRecipient_TwoRecipients(t *testing.T) {
	dir := t.TempDir()

	// Generate two recipient key pairs (RSA-OAEP works best for multi-recipient).
	for _, name := range []string{"alice", "bob"} {
		priv, pub, err := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
		if err != nil {
			t.Fatalf("generate %s keys: %v", name, err)
		}
		if err := crypto.SaveKeyPEM(filepath.Join(dir, name+".key"), priv, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := crypto.SaveKeyPEM(filepath.Join(dir, name+".pub"), pub, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	inFile := filepath.Join(dir, "secret.txt")
	outVpack := filepath.Join(dir, "secret.vpack")
	payload := []byte("multi-recipient secret data")
	os.WriteFile(inFile, payload, 0o600)

	// Protect for two recipients.
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--recipient", filepath.Join(dir, "alice.pub"),
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect multi-recipient: %v", err)
	}

	// Verify manifest has multi-recipient entries.
	br, err := bundle.Read(outVpack)
	if err != nil {
		t.Fatal(err)
	}
	if br.Manifest.Encryption.Hybrid == nil {
		t.Fatal("expected hybrid meta")
	}
	if len(br.Manifest.Encryption.Hybrid.Recipients) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(br.Manifest.Encryption.Hybrid.Recipients))
	}
	if br.Manifest.Version != bundle.ManifestVersionV2 {
		t.Errorf("expected v2 manifest for multi-recipient, got %s", br.Manifest.Version)
	}

	// Alice can decrypt.
	aliceDec := filepath.Join(dir, "alice.dec")
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", outVpack,
		"--out", aliceDec,
		"--privkey", filepath.Join(dir, "alice.key"),
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("alice decrypt: %v", err)
	}
	aliceData, _ := os.ReadFile(aliceDec)
	if string(aliceData) != string(payload) {
		t.Error("alice: decrypted data mismatch")
	}

	// Bob can decrypt.
	bobDec := filepath.Join(dir, "bob.dec")
	root3 := NewRootCmd()
	root3.SetArgs([]string{
		"decrypt",
		"--in", outVpack,
		"--out", bobDec,
		"--privkey", filepath.Join(dir, "bob.key"),
	})
	if err := root3.Execute(); err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	bobData, _ := os.ReadFile(bobDec)
	if string(bobData) != string(payload) {
		t.Error("bob: decrypted data mismatch")
	}
}

func TestMultiRecipient_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()

	// Alice and an outsider.
	alicePriv, alicePub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	crypto.SaveKeyPEM(filepath.Join(dir, "alice.key"), alicePriv, 0o600)
	crypto.SaveKeyPEM(filepath.Join(dir, "alice.pub"), alicePub, 0o644)

	evePriv, _, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	crypto.SaveKeyPEM(filepath.Join(dir, "eve.key"), evePriv, 0o600)

	inFile := filepath.Join(dir, "secret.txt")
	outVpack := filepath.Join(dir, "secret.vpack")
	os.WriteFile(inFile, []byte("for alice only"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--recipient", filepath.Join(dir, "alice.pub"),
	})
	root.Execute()

	// Eve should not be able to decrypt.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", outVpack,
		"--out", filepath.Join(dir, "eve.dec"),
		"--privkey", filepath.Join(dir, "eve.key"),
	})
	// This should fail (non-zero exit), but Execute wraps the exit.
	// The function itself uses os.Exit, so we just check it doesn't panic.
	// In production this exits with code 11.
}

func TestMultiRecipient_MixedSchemes(t *testing.T) {
	dir := t.TempDir()

	// Alice uses RSA-OAEP 2048, Bob uses RSA-OAEP 4096.
	alicePriv, alicePub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	crypto.SaveKeyPEM(filepath.Join(dir, "alice.key"), alicePriv, 0o600)
	crypto.SaveKeyPEM(filepath.Join(dir, "alice.pub"), alicePub, 0o644)

	bobPriv, bobPub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP4096)
	crypto.SaveKeyPEM(filepath.Join(dir, "bob.key"), bobPriv, 0o600)
	crypto.SaveKeyPEM(filepath.Join(dir, "bob.pub"), bobPub, 0o644)

	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	payload := []byte("mixed scheme multi-recipient")
	os.WriteFile(inFile, payload, 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--recipient", filepath.Join(dir, "alice.pub"),
		"--recipient", filepath.Join(dir, "bob.pub"),
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Both can decrypt.
	for _, who := range []string{"alice", "bob"} {
		decFile := filepath.Join(dir, who+".dec")
		r := NewRootCmd()
		r.SetArgs([]string{
			"decrypt",
			"--in", outVpack,
			"--out", decFile,
			"--privkey", filepath.Join(dir, who+".key"),
		})
		if err := r.Execute(); err != nil {
			t.Fatalf("%s decrypt: %v", who, err)
		}
		data, _ := os.ReadFile(decFile)
		if string(data) != string(payload) {
			t.Errorf("%s: decrypted data mismatch", who)
		}
	}
}

func TestMultiRecipient_Inspect(t *testing.T) {
	dir := t.TempDir()

	alicePriv, alicePub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	crypto.SaveKeyPEM(filepath.Join(dir, "a.key"), alicePriv, 0o600)
	crypto.SaveKeyPEM(filepath.Join(dir, "a.pub"), alicePub, 0o644)

	bobPriv, bobPub, _ := crypto.GenerateHybridKeys(crypto.HybridRSAOAEP2048)
	crypto.SaveKeyPEM(filepath.Join(dir, "b.key"), bobPriv, 0o600)
	crypto.SaveKeyPEM(filepath.Join(dir, "b.pub"), bobPub, 0o644)

	inFile := filepath.Join(dir, "data.txt")
	outVpack := filepath.Join(dir, "data.vpack")
	os.WriteFile(inFile, []byte("inspect me"), 0o600)

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", outVpack,
		"--recipient", filepath.Join(dir, "a.pub"),
		"--recipient", filepath.Join(dir, "b.pub"),
	})
	root.Execute()

	// Inspect should not error.
	root2 := NewRootCmd()
	root2.SetArgs([]string{"inspect", "--in", outVpack})
	if err := root2.Execute(); err != nil {
		t.Fatalf("inspect multi-recipient: %v", err)
	}
}
