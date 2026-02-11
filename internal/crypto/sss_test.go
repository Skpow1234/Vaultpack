package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitCombine_RoundTrip(t *testing.T) {
	secret := []byte("top-secret-encryption-key-32byte!")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Combine using exactly 3 shares (threshold).
	got, err := CombineShares(shares[:3])
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("reconstructed secret does not match")
	}
}

func TestSplitCombine_DifferentShareSubsets(t *testing.T) {
	secret := []byte("another-secret-value")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// Try different subsets of 3 shares.
	subsets := [][3]int{
		{0, 1, 2},
		{0, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
		{0, 1, 4},
	}

	for _, s := range subsets {
		subset := []*Share{shares[s[0]], shares[s[1]], shares[s[2]]}
		got, err := CombineShares(subset[:])
		if err != nil {
			t.Errorf("CombineShares(%v): %v", s, err)
			continue
		}
		if !bytes.Equal(got, secret) {
			t.Errorf("CombineShares(%v): secret mismatch", s)
		}
	}
}

func TestSplitCombine_ExtraShares(t *testing.T) {
	secret := []byte("we-have-more-than-threshold")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// Provide 4 shares (more than threshold of 3).
	got, err := CombineShares(shares[:4])
	if err != nil {
		t.Fatalf("CombineShares with 4 shares: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("secret mismatch")
	}
}

func TestSplitCombine_InsufficientShares(t *testing.T) {
	secret := []byte("insufficient-shares-test")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	_, err = CombineShares(shares[:2])
	if err == nil {
		t.Fatal("expected error for insufficient shares")
	}
}

func TestSplitCombine_DuplicateShares(t *testing.T) {
	secret := []byte("duplicate-share-test")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// Duplicate share 0.
	dupes := []*Share{shares[0], shares[1], shares[0]}
	_, err = CombineShares(dupes)
	if err == nil {
		t.Fatal("expected error for duplicate shares")
	}
}

func TestSplitCombine_TamperedShare(t *testing.T) {
	secret := []byte("tamper-detection-test")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// Tamper with one share's data.
	tampered := *shares[0]
	tampered.Data = make([]byte, len(shares[0].Data))
	copy(tampered.Data, shares[0].Data)
	tampered.Data[0] ^= 0xFF

	tamperedSet := []*Share{&tampered, shares[1], shares[2]}
	_, err = CombineShares(tamperedSet)
	if err == nil {
		t.Fatal("expected error for tampered share (checksum mismatch)")
	}
}

func TestSplitCombine_MinimalNK(t *testing.T) {
	// Minimum: 2-of-2.
	secret := []byte("two-of-two")
	shares, err := SplitSecret(secret, 2, 2)
	if err != nil {
		t.Fatalf("SplitSecret 2/2: %v", err)
	}
	got, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares 2/2: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret mismatch for 2/2")
	}
}

func TestSplitCombine_LargeSecret(t *testing.T) {
	// Test with a larger secret (256 bytes).
	secret := make([]byte, 256)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecret large: %v", err)
	}
	got, err := CombineShares(shares[:3])
	if err != nil {
		t.Fatalf("CombineShares large: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("large secret mismatch")
	}
}

func TestSplitCombine_MaxShares(t *testing.T) {
	// Test with 255 shares, threshold 2.
	secret := []byte("max-shares-test")
	shares, err := SplitSecret(secret, 255, 2)
	if err != nil {
		t.Fatalf("SplitSecret 255/2: %v", err)
	}
	if len(shares) != 255 {
		t.Fatalf("expected 255 shares, got %d", len(shares))
	}

	// Use shares 100 and 200.
	got, err := CombineShares([]*Share{shares[99], shares[199]})
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret mismatch")
	}
}

func TestSplit_InvalidParams(t *testing.T) {
	secret := []byte("test")

	tests := []struct {
		name string
		n, k int
	}{
		{"n=0", 0, 0},
		{"n=1", 1, 1},
		{"k>n", 3, 5},
		{"n=256", 256, 2},
		{"k=0", 5, 0},
		{"k=1", 5, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SplitSecret(secret, tt.n, tt.k)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSplit_EmptySecret(t *testing.T) {
	_, err := SplitSecret(nil, 5, 3)
	if err == nil {
		t.Fatal("expected error for nil secret")
	}
	_, err = SplitSecret([]byte{}, 5, 3)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestMarshalUnmarshalShare(t *testing.T) {
	secret := []byte("marshal-unmarshal-test")
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range shares {
		data := MarshalShare(s)
		parsed, err := UnmarshalShare(data)
		if err != nil {
			t.Fatalf("UnmarshalShare(share %d): %v", s.Index, err)
		}
		if parsed.Index != s.Index {
			t.Errorf("index mismatch: %d vs %d", parsed.Index, s.Index)
		}
		if parsed.Threshold != s.Threshold {
			t.Errorf("threshold mismatch")
		}
		if parsed.Total != s.Total {
			t.Errorf("total mismatch")
		}
		if parsed.KeyLen != s.KeyLen {
			t.Errorf("keylen mismatch")
		}
		if parsed.Checksum != s.Checksum {
			t.Errorf("checksum mismatch")
		}
		if !bytes.Equal(parsed.Data, s.Data) {
			t.Errorf("data mismatch")
		}
	}
}

func TestUnmarshalShare_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte("short")},
		{"bad header", []byte("INVALID-HEADER\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")},
		{"truncated data", append([]byte(ShareFileHeader), 1, 3, 5, 0, 32, 0, 0, 0, 0)}, // keyLen=32 but no data
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalShare(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestGF256Mul verifies multiplication properties.
func TestGF256Mul(t *testing.T) {
	// Identity: a*1 = a
	if gf256Mul(42, 1) != 42 {
		t.Error("a*1 != a")
	}
	// Zero: a*0 = 0
	if gf256Mul(42, 0) != 0 {
		t.Error("a*0 != 0")
	}
	// Commutativity: a*b = b*a
	if gf256Mul(0x53, 0xCA) != gf256Mul(0xCA, 0x53) {
		t.Error("a*b != b*a")
	}
}

// TestGF256Inv verifies inverses.
func TestGF256Inv(t *testing.T) {
	for a := 1; a < 256; a++ {
		inv := gf256Inv(byte(a))
		if gf256Mul(byte(a), inv) != 1 {
			t.Errorf("a=%d, inv=%d, a*inv=%d (expected 1)", a, inv, gf256Mul(byte(a), inv))
		}
	}
}

func TestCombineShares_ThresholdMismatch(t *testing.T) {
	s1 := &Share{Index: 1, Threshold: 3, Total: 5, KeyLen: 4, Data: []byte{1, 2, 3, 4}}
	s2 := &Share{Index: 2, Threshold: 2, Total: 5, KeyLen: 4, Data: []byte{5, 6, 7, 8}} // different threshold
	s3 := &Share{Index: 3, Threshold: 3, Total: 5, KeyLen: 4, Data: []byte{9, 10, 11, 12}}

	_, err := CombineShares([]*Share{s1, s2, s3})
	if err == nil {
		t.Fatal("expected threshold mismatch error")
	}
}
