package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestProtectDecrypt_ParallelWorkers(t *testing.T) {
	for _, workers := range []int{2, 4} {
		t.Run("w="+strconv.Itoa(workers), func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "input.bin")
			out := filepath.Join(dir, "input.vpack")
			keyPath := filepath.Join(dir, "input.key")
			dec := filepath.Join(dir, "input.dec")

			pt := make([]byte, 5*64*1024+13)
			if _, err := rand.Read(pt); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(in, pt, 0o600); err != nil {
				t.Fatal(err)
			}

			root := NewRootCmd()
			root.SetArgs([]string{
				"protect",
				"--in", in,
				"--out", out,
				"--key-out", keyPath,
				"--parallel-workers", strconv.Itoa(workers),
			})
			if err := root.Execute(); err != nil {
				t.Fatalf("protect: %v", err)
			}

			root2 := NewRootCmd()
			root2.SetArgs([]string{
				"decrypt",
				"--in", out,
				"--key", keyPath,
				"--out", dec,
				"--parallel-workers", strconv.Itoa(workers),
			})
			if err := root2.Execute(); err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			got, err := os.ReadFile(dec)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(got), len(pt))
			}
		})
	}
}
