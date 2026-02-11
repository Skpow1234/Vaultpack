package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	lblake3 "lukechampine.com/blake3"
)

// SupportedHashAlgos is the list of all supported hash algorithm names, in
// presentation order.
var SupportedHashAlgos = []string{
	"sha256",
	"sha512",
	"sha3-256",
	"sha3-512",
	"blake2b-256",
	"blake2b-512",
	"blake3",
}

// SupportedHashAlgo checks whether the given algorithm name is supported.
func SupportedHashAlgo(algo string) bool {
	switch algo {
	case "sha256", "sha512",
		"sha3-256", "sha3-512",
		"blake2b-256", "blake2b-512",
		"blake3":
		return true
	default:
		return false
	}
}

// newHash returns a hash.Hash for the named algorithm.
func newHash(algo string) (hash.Hash, error) {
	switch algo {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	case "sha3-256":
		return sha3.New256(), nil
	case "sha3-512":
		return sha3.New512(), nil
	case "blake2b-256":
		h, err := blake2b.New256(nil)
		if err != nil {
			return nil, fmt.Errorf("blake2b-256: %w", err)
		}
		return h, nil
	case "blake2b-512":
		h, err := blake2b.New512(nil)
		if err != nil {
			return nil, fmt.Errorf("blake2b-512: %w", err)
		}
		return h, nil
	case "blake3":
		return lblake3.New(32, nil), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", algo)
	}
}

// HashReader computes a hash digest over r using the named algorithm.
// It returns the raw digest bytes.
func HashReader(r io.Reader, algo string) ([]byte, error) {
	h, err := newHash(algo)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("hash %s: %w", algo, err)
	}
	return h.Sum(nil), nil
}

// HashDigestSize returns the digest size in bytes for the named algorithm.
func HashDigestSize(algo string) (int, error) {
	h, err := newHash(algo)
	if err != nil {
		return 0, err
	}
	return h.Size(), nil
}
