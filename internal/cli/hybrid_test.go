package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
)

// TestHybridProtectDecrypt_AllSchemes performs a full CLI round-trip for every hybrid scheme.
func TestHybridProtectDecrypt_AllSchemes(t *testing.T) {
	for _, scheme := range crypto.SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()
			inFile := filepath.Join(dir, "data.txt")
			bundlePath := filepath.Join(dir, "data.vpack")
			outFile := filepath.Join(dir, "recovered.txt")
			privPath := filepath.Join(dir, "recipient.key")
			pubPath := filepath.Join(dir, "recipient.pub")

			original := []byte("hybrid encryption test for " + scheme)
			os.WriteFile(inFile, original, 0o600)

			// Generate recipient keys.
			root := NewRootCmd()
			root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "recipient"), "--algo", scheme})
			if err := root.Execute(); err != nil {
				t.Fatalf("keygen: %v", err)
			}

			// Protect with --recipient.
			root2 := NewRootCmd()
			root2.SetArgs([]string{
				"protect",
				"--in", inFile,
				"--out", bundlePath,
				"--recipient", pubPath,
			})
			if err := root2.Execute(); err != nil {
				t.Fatalf("protect: %v", err)
			}

			// Verify bundle has hybrid meta.
			br, err := bundle.Read(bundlePath)
			if err != nil {
				t.Fatalf("read bundle: %v", err)
			}
			if br.Manifest.Encryption.Hybrid == nil {
				t.Fatal("expected hybrid meta in manifest")
			}
			if br.Manifest.Encryption.Hybrid.Scheme != scheme {
				t.Errorf("scheme: got %s, want %s", br.Manifest.Encryption.Hybrid.Scheme, scheme)
			}

			// Decrypt with --privkey.
			root3 := NewRootCmd()
			root3.SetArgs([]string{
				"decrypt",
				"--in", bundlePath,
				"--out", outFile,
				"--privkey", privPath,
			})
			if err := root3.Execute(); err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			recovered, _ := os.ReadFile(outFile)
			if string(recovered) != string(original) {
				t.Errorf("recovered %q, want %q", recovered, original)
			}
		})
	}
}

// TestHybridProtectDecrypt_WithSign verifies hybrid + signing combo.
func TestHybridProtectDecrypt_WithSign(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	bundlePath := filepath.Join(dir, "data.vpack")
	outFile := filepath.Join(dir, "recovered.txt")

	original := []byte("hybrid + sign test")
	os.WriteFile(inFile, original, 0o600)

	// Generate recipient keys (X25519).
	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "recipient"), "--algo", "x25519-aes-256-gcm"})
	root.Execute()

	// Generate signing keys.
	root2 := NewRootCmd()
	root2.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "signer")})
	root2.Execute()

	// Protect with --recipient + --sign.
	root3 := NewRootCmd()
	root3.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundlePath,
		"--recipient", filepath.Join(dir, "recipient.pub"),
		"--sign",
		"--signing-priv", filepath.Join(dir, "signer.key"),
	})
	if err := root3.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Verify signature.
	root4 := NewRootCmd()
	root4.SetArgs([]string{"verify", "--in", bundlePath, "--pubkey", filepath.Join(dir, "signer.pub")})
	if err := root4.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Decrypt with --privkey.
	root5 := NewRootCmd()
	root5.SetArgs([]string{
		"decrypt",
		"--in", bundlePath,
		"--out", outFile,
		"--privkey", filepath.Join(dir, "recipient.key"),
	})
	if err := root5.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	recovered, _ := os.ReadFile(outFile)
	if string(recovered) != string(original) {
		t.Errorf("recovered %q, want %q", recovered, original)
	}
}

// TestHybridInspect verifies inspect shows hybrid info.
func TestHybridInspect(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "data.txt")
	bundlePath := filepath.Join(dir, "data.vpack")

	os.WriteFile(inFile, []byte("inspect hybrid test"), 0o600)

	// Generate keys.
	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "r"), "--algo", "x25519-aes-256-gcm"})
	root.Execute()

	// Protect.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundlePath,
		"--recipient", filepath.Join(dir, "r.pub"),
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// Inspect.
	root3 := NewRootCmd()
	root3.SetArgs([]string{"inspect", "--in", bundlePath})
	if err := root3.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}

// TestHybridKeygenAllSchemes_CLI verifies keygen works for all hybrid schemes via CLI.
func TestHybridKeygenAllSchemes_CLI(t *testing.T) {
	for _, scheme := range crypto.SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()
			root := NewRootCmd()
			root.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "key"), "--algo", scheme})
			if err := root.Execute(); err != nil {
				t.Fatalf("keygen %s: %v", scheme, err)
			}

			privPath := filepath.Join(dir, "key.key")
			pubPath := filepath.Join(dir, "key.pub")

			if _, err := os.Stat(privPath); os.IsNotExist(err) {
				t.Fatal("private key not created")
			}
			if _, err := os.Stat(pubPath); os.IsNotExist(err) {
				t.Fatal("public key not created")
			}
		})
	}
}

// TestRecipientAndKeyMutuallyExclusive verifies flags can't be mixed.
func TestRecipientAndKeyMutuallyExclusive(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", "dummy",
		"--recipient", "dummy.pub",
		"--key", "dummy.key",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when both --recipient and --key are set")
	}
}

// TestRecipientAndPasswordMutuallyExclusive verifies flags can't be mixed.
func TestRecipientAndPasswordMutuallyExclusive(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", "dummy",
		"--recipient", "dummy.pub",
		"--password", "pw",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when both --recipient and --password are set")
	}
}
