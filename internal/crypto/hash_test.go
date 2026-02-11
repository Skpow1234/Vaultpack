package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Known-answer vectors: SHA-256 of "" (empty string).
func TestHashReader_SHA256_KnownVector(t *testing.T) {
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

// TestSupportedHashAlgo confirms all 8 algorithms are recognized.
func TestSupportedHashAlgo(t *testing.T) {
	tests := []struct {
		algo string
		want bool
	}{
		{"sha256", true},
		{"sha512", true},
		{"sha3-256", true},
		{"sha3-512", true},
		{"blake2b-256", true},
		{"blake2b-512", true},
		{"blake3", true},
		{"SHA256", false},
		{"md5", false},
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

// TestHashReader_AllAlgos_Empty verifies that all algorithms produce the correct
// digest length when hashing an empty input (known-answer test).
func TestHashReader_AllAlgos_Empty(t *testing.T) {
	// Expected digest of "" in hex for each algo.
	wantHex := map[string]string{
		"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha512":     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"sha3-256":   "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"sha3-512":   "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		"blake2b-256": "0e5751c9b024a462058ce3a5b110d7309f6bf652fc905675c3be966b225e3564" + "", // 32 bytes
		"blake2b-512": "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		"blake3":      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
	}

	for algo, want := range wantHex {
		t.Run(algo, func(t *testing.T) {
			digest, err := HashReader(strings.NewReader(""), algo)
			if err != nil {
				t.Fatalf("HashReader(%q, ''): %v", algo, err)
			}
			got := hex.EncodeToString(digest)
			if got != want {
				t.Errorf("%s('') = %s, want %s", algo, got, want)
			}
		})
	}
}

// TestHashReader_AllAlgos_Hello verifies that all algorithms produce the expected
// digest size for a non-empty input.
func TestHashReader_AllAlgos_Hello(t *testing.T) {
	wantSize := map[string]int{
		"sha256":      32,
		"sha512":      64,
		"sha3-256":    32,
		"sha3-512":    64,
		"blake2b-256": 32,
		"blake2b-512": 64,
		"blake3":      32,
	}

	for algo, size := range wantSize {
		t.Run(algo, func(t *testing.T) {
			digest, err := HashReader(strings.NewReader("hello world"), algo)
			if err != nil {
				t.Fatalf("HashReader(%q, 'hello world'): %v", algo, err)
			}
			if len(digest) != size {
				t.Errorf("%s digest length = %d, want %d", algo, len(digest), size)
			}
		})
	}
}

// TestHashReader_Deterministic ensures same input produces same hash.
func TestHashReader_Deterministic(t *testing.T) {
	data := "deterministic test payload 1234567890"
	for _, algo := range SupportedHashAlgos {
		t.Run(algo, func(t *testing.T) {
			d1, err := HashReader(strings.NewReader(data), algo)
			if err != nil {
				t.Fatal(err)
			}
			d2, err := HashReader(strings.NewReader(data), algo)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(d1, d2) {
				t.Errorf("%s: same input produced different digests", algo)
			}
		})
	}
}

// TestHashDigestSize confirms the reported sizes match actual output.
func TestHashDigestSize(t *testing.T) {
	for _, algo := range SupportedHashAlgos {
		t.Run(algo, func(t *testing.T) {
			reported, err := HashDigestSize(algo)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := HashReader(strings.NewReader("test"), algo)
			if err != nil {
				t.Fatal(err)
			}
			if len(digest) != reported {
				t.Errorf("%s: HashDigestSize=%d but actual=%d", algo, reported, len(digest))
			}
		})
	}
}
