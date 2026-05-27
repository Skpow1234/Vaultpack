package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

func TestKeySource_ProtectDecryptEnv(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "plain.txt")
	bundleFile := filepath.Join(dir, "plain.vpack")
	outFile := filepath.Join(dir, "plain.out")
	plaintext := []byte("key-source round trip")
	if err := os.WriteFile(inFile, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, crypto.AES256KeySize)
	for i := range key {
		key[i] = byte(255 - i)
	}
	t.Setenv("VP_TEST_KEYSOURCE_KEY", crypto.KeyFilePrefix+util.B64Encode(key))

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-source", "env://VP_TEST_KEYSOURCE_KEY",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect --key-source: %v", err)
	}

	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", bundleFile,
		"--out", outFile,
		"--key-source", "b64://" + util.B64Encode(key),
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("decrypt --key-source: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestSigningKeySource_SignVerify(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "plain.txt")
	bundleFile := filepath.Join(dir, "plain.vpack")
	keyFile := filepath.Join(dir, "plain.key")
	if err := os.WriteFile(inFile, []byte("signing key source"), 0o600); err != nil {
		t.Fatal(err)
	}

	keygen := NewRootCmd()
	keygen.SetArgs([]string{"keygen", "--out", filepath.Join(dir, "signing")})
	if err := keygen.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	protect := NewRootCmd()
	protect.SetArgs([]string{
		"protect",
		"--in", inFile,
		"--out", bundleFile,
		"--key-out", keyFile,
	})
	if err := protect.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	signPriv, err := os.ReadFile(filepath.Join(dir, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VP_TEST_SIGNING_KEY", string(signPriv))

	sign := NewRootCmd()
	sign.SetArgs([]string{
		"sign",
		"--in", bundleFile,
		"--signing-key-source", "env://VP_TEST_SIGNING_KEY",
	})
	if err := sign.Execute(); err != nil {
		t.Fatalf("sign --signing-key-source: %v", err)
	}

	verify := NewRootCmd()
	verify.SetArgs([]string{"verify", "--in", bundleFile, "--pubkey", filepath.Join(dir, "signing.pub")})
	if err := verify.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
