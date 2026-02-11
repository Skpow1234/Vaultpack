// Package crypto implements Shamir's Secret Sharing over GF(256).
//
// Each byte of the secret is split independently using a random polynomial
// of degree (threshold-1) over the Galois field GF(2^8). The field uses the
// irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B, same as AES).
//
// Share format (per share file):
//
//	Header: "VAULTPACK-SHARE-V1\n"
//	Index:  1-byte share index (1..N, never 0)
//	Threshold: 1-byte threshold K
//	Total:  1-byte total shares N
//	KeyLen: 2-byte big-endian original secret length
//	Checksum: 4-byte SHA-256 prefix of the original secret (for tamper detection)
//	Data:   len(secret) bytes of share data
//
// Reconstruction uses Lagrange interpolation over GF(256).
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	// ShareFileHeader identifies a VaultPack share file.
	ShareFileHeader = "VAULTPACK-SHARE-V1\n"
	// shareHeaderSize = len(header) + 1(index) + 1(threshold) + 1(total) + 2(keyLen) + 4(checksum)
	shareMetaSize = 1 + 1 + 1 + 2 + 4 // 9 bytes after the header
)

// Share represents one share of a split secret.
type Share struct {
	Index     byte   // 1-based share index (1..N)
	Threshold byte   // K: minimum shares needed
	Total     byte   // N: total shares created
	KeyLen    uint16 // original secret length
	Checksum  [4]byte // first 4 bytes of SHA-256(secret)
	Data      []byte // share data (len == KeyLen)
}

// MarshalShare serializes a Share into the wire format.
func MarshalShare(s *Share) []byte {
	hdr := []byte(ShareFileHeader)
	buf := make([]byte, len(hdr)+shareMetaSize+len(s.Data))
	copy(buf, hdr)
	off := len(hdr)
	buf[off] = s.Index
	buf[off+1] = s.Threshold
	buf[off+2] = s.Total
	binary.BigEndian.PutUint16(buf[off+3:off+5], s.KeyLen)
	copy(buf[off+5:off+9], s.Checksum[:])
	copy(buf[off+9:], s.Data)
	return buf
}

// UnmarshalShare deserializes the wire format into a Share.
func UnmarshalShare(data []byte) (*Share, error) {
	hdr := []byte(ShareFileHeader)
	if len(data) < len(hdr)+shareMetaSize {
		return nil, fmt.Errorf("share data too short")
	}
	for i, b := range hdr {
		if data[i] != b {
			return nil, fmt.Errorf("invalid share header")
		}
	}
	off := len(hdr)
	s := &Share{
		Index:     data[off],
		Threshold: data[off+1],
		Total:     data[off+2],
		KeyLen:    binary.BigEndian.Uint16(data[off+3 : off+5]),
	}
	copy(s.Checksum[:], data[off+5:off+9])

	dataStart := off + shareMetaSize
	if len(data) < dataStart+int(s.KeyLen) {
		return nil, fmt.Errorf("share data truncated: expected %d bytes, got %d", s.KeyLen, len(data)-dataStart)
	}
	s.Data = make([]byte, s.KeyLen)
	copy(s.Data, data[dataStart:dataStart+int(s.KeyLen)])

	if s.Index == 0 {
		return nil, fmt.Errorf("share index must be 1..255, got 0")
	}
	if s.Threshold == 0 {
		return nil, fmt.Errorf("threshold must be >= 1")
	}
	if s.Total == 0 {
		return nil, fmt.Errorf("total must be >= 1")
	}
	if s.Threshold > s.Total {
		return nil, fmt.Errorf("threshold %d exceeds total %d", s.Threshold, s.Total)
	}

	return s, nil
}

// SplitSecret splits a secret into n shares with a threshold of k.
// k shares are needed to reconstruct; fewer reveal nothing.
// n must be in [2..255] and k in [2..n].
func SplitSecret(secret []byte, n, k int) ([]*Share, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}
	if n < 2 || n > 255 {
		return nil, fmt.Errorf("n must be in [2..255], got %d", n)
	}
	if k < 2 || k > n {
		return nil, fmt.Errorf("k must be in [2..n], got k=%d n=%d", k, n)
	}
	if len(secret) > 65535 {
		return nil, fmt.Errorf("secret too long: max 65535 bytes, got %d", len(secret))
	}

	// Compute checksum (first 4 bytes of SHA-256).
	h := sha256.Sum256(secret)
	var checksum [4]byte
	copy(checksum[:], h[:4])

	// For each byte of the secret, create a random polynomial of degree k-1
	// where the constant term is the secret byte.
	shares := make([]*Share, n)
	for i := 0; i < n; i++ {
		shares[i] = &Share{
			Index:     byte(i + 1),
			Threshold: byte(k),
			Total:     byte(n),
			KeyLen:    uint16(len(secret)),
			Checksum:  checksum,
			Data:      make([]byte, len(secret)),
		}
	}

	// Random coefficients buffer: k-1 coefficients per secret byte.
	coeffs := make([]byte, k-1)

	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// Generate random coefficients for this byte's polynomial.
		if _, err := rand.Read(coeffs); err != nil {
			return nil, fmt.Errorf("random coefficients: %w", err)
		}

		// Evaluate the polynomial at x = share.Index for each share.
		for i := 0; i < n; i++ {
			x := shares[i].Index
			// p(x) = secret[byteIdx] + coeffs[0]*x + coeffs[1]*x^2 + ...
			shares[i].Data[byteIdx] = gf256Eval(secret[byteIdx], coeffs, x)
		}
	}

	return shares, nil
}

// CombineShares reconstructs the secret from k or more shares using
// Lagrange interpolation over GF(256).
func CombineShares(shares []*Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	k := int(shares[0].Threshold)
	keyLen := int(shares[0].KeyLen)
	checksum := shares[0].Checksum

	if len(shares) < k {
		return nil, fmt.Errorf("need at least %d shares, got %d", k, len(shares))
	}

	// Validate all shares are compatible.
	seen := make(map[byte]bool)
	for _, s := range shares {
		if int(s.Threshold) != k {
			return nil, fmt.Errorf("threshold mismatch: share %d has threshold %d, expected %d", s.Index, s.Threshold, k)
		}
		if int(s.KeyLen) != keyLen {
			return nil, fmt.Errorf("key length mismatch: share %d has %d, expected %d", s.Index, s.KeyLen, keyLen)
		}
		if s.Checksum != checksum {
			return nil, fmt.Errorf("checksum mismatch on share %d: shares may be from different secrets", s.Index)
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}

	// Use exactly k shares for interpolation.
	useShares := shares[:k]

	// Lagrange interpolation at x=0 for each byte position.
	secret := make([]byte, keyLen)
	for byteIdx := 0; byteIdx < keyLen; byteIdx++ {
		secret[byteIdx] = gf256Interpolate(useShares, byteIdx)
	}

	// Verify checksum.
	h := sha256.Sum256(secret)
	var gotChecksum [4]byte
	copy(gotChecksum[:], h[:4])
	if gotChecksum != checksum {
		return nil, fmt.Errorf("reconstructed secret checksum mismatch: shares may be corrupted or from different secrets")
	}

	return secret, nil
}

// --- GF(256) arithmetic ---
// Uses the AES field polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B).

// gf256Mul multiplies two elements in GF(256) using Russian peasant multiplication.
func gf256Mul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0x1B // reduce mod x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return result
}

// gf256Inv computes the multiplicative inverse of a in GF(256).
// Uses exponentiation: a^254 = a^(-1) in GF(2^8).
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0 // undefined, but returning 0 avoids panics
	}
	// a^(2^8 - 2) = a^254
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result)
		result = gf256Mul(result, a)
	}
	result = gf256Mul(result, result)
	return result
}

// gf256Eval evaluates polynomial p(x) = constant + coeffs[0]*x + coeffs[1]*x^2 + ...
// using Horner's method.
func gf256Eval(constant byte, coeffs []byte, x byte) byte {
	// Horner's method from highest degree down.
	result := byte(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gf256Mul(result, x) ^ coeffs[i]
	}
	result = gf256Mul(result, x) ^ constant
	return result
}

// gf256Interpolate performs Lagrange interpolation at x=0 over GF(256)
// for a specific byte position across shares.
func gf256Interpolate(shares []*Share, byteIdx int) byte {
	k := len(shares)
	result := byte(0)

	for i := 0; i < k; i++ {
		xi := shares[i].Index
		yi := shares[i].Data[byteIdx]

		// Compute Lagrange basis polynomial l_i(0) = product_{j!=i} (0-xj)/(xi-xj)
		// In GF(256): 0-xj = xj (since additive inverse is the same as the element)
		// So l_i(0) = product_{j!=i} xj / (xi ^ xj)
		basis := byte(1)
		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			xj := shares[j].Index
			num := xj
			den := xi ^ xj // subtraction in GF(2^8) is XOR
			basis = gf256Mul(basis, gf256Mul(num, gf256Inv(den)))
		}

		result ^= gf256Mul(yi, basis)
	}

	return result
}
