package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashReader_SHA256_KnownVector(t *testing.T) {
	// SHA-256 of "" (empty string) is well-known.
	input := ""
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	digest, err := HashReader(strings.NewReader(input), "sha256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := hex.EncodeToString(digest)
	if got != want {
		t.Errorf("SHA-256('') = %s, want %s", got, want)
	}
}

func TestHashReader_SHA256_HelloWorld(t *testing.T) {
	input := "hello world"
	h := sha256.Sum256([]byte(input))
	want := h[:]

	digest, err := HashReader(strings.NewReader(input), "sha256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(digest, want) {
		t.Errorf("digest mismatch")
	}
}

func TestHashReader_UnsupportedAlgo(t *testing.T) {
	_, err := HashReader(strings.NewReader("data"), "md5")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestSupportedHashAlgo(t *testing.T) {
	tests := []struct {
		algo string
		want bool
	}{
		{"sha256", true},
		{"SHA256", false},
		{"md5", false},
		{"blake3", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			if got := SupportedHashAlgo(tt.algo); got != tt.want {
				t.Errorf("SupportedHashAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}
