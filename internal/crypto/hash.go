package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// SupportedHashAlgo checks whether the given algorithm name is supported.
func SupportedHashAlgo(algo string) bool {
	switch algo {
	case "sha256":
		return true
	default:
		return false
	}
}

// HashReader computes a hash digest over r using the named algorithm.
// It returns the raw digest bytes. Supports "sha256".
func HashReader(r io.Reader, algo string) ([]byte, error) {
	switch algo {
	case "sha256":
		return hashSHA256(r)
	default:
		return nil, fmt.Errorf("hash: unsupported algorithm %q", algo)
	}
}

func hashSHA256(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("hash sha256: %w", err)
	}
	return h.Sum(nil), nil
}
