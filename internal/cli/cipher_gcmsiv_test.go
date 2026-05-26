package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectDecrypt_AES256GCMSIV(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.txt")
	out := filepath.Join(dir, "input.vpack")
	key := filepath.Join(dir, "input.key")
	decrypted := filepath.Join(dir, "input.dec")

	if err := os.WriteFile(in, []byte("hello aes-256-gcm-siv"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	root.SetArgs([]string{
		"protect",
		"--in", in,
		"--out", out,
		"--key-out", key,
		"--cipher", "aes-256-gcm-siv",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"decrypt",
		"--in", out,
		"--key", key,
		"--out", decrypted,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello aes-256-gcm-siv" {
		t.Errorf("decrypted: %q", got)
	}
}
