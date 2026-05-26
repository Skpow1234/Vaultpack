package aesgcmsiv

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 8452 Appendix C.2 test vectors for AEAD_AES_256_GCM_SIV.
var aes256TestVectors = []struct {
	name       string
	key        string
	nonce      string
	aad        string
	plaintext  string
	ciphertext string
}{
	{
		name:       "Empty plaintext and AAD",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "",
		ciphertext: "07f5f4169bbf55a8400cd47ea6fd400f",
	},
	{
		name:       "8-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "0100000000000000",
		ciphertext: "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
	},
	{
		name:       "16-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "01000000000000000000000000000000",
		ciphertext: "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
	},
	{
		name:       "1-byte AAD, 8-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "01",
		plaintext:  "0200000000000000",
		ciphertext: "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
	},
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRFC8452VectorsAES256(t *testing.T) {
	for _, tc := range aes256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustDecodeHex(tc.key)
			nonce := mustDecodeHex(tc.nonce)
			aad := mustDecodeHex(tc.aad)
			plaintext := mustDecodeHex(tc.plaintext)
			expectedCiphertext := mustDecodeHex(tc.ciphertext)

			aead, err := New(key)
			if err != nil {
				t.Fatal(err)
			}
			ct := aead.Seal(nil, nonce, plaintext, aad)
			if !bytes.Equal(ct, expectedCiphertext) {
				t.Errorf("Seal mismatch:\n got: %x\n want: %x", ct, expectedCiphertext)
			}
			pt, err := aead.Open(nil, nonce, ct, aad)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("Open mismatch:\n got: %x\n want: %x", pt, plaintext)
			}
		})
	}
}

func TestCipherInterface(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := New(key)
	var _ cipher.AEAD = aead
}

func TestAuthFailure(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	ct := aead.Seal(nil, nonce, []byte("msg"), []byte("aad"))
	tampered := append([]byte{}, ct...)
	tampered[0] ^= 0xff
	if _, err := aead.Open(nil, nonce, tampered, []byte("aad")); err != ErrOpen {
		t.Errorf("expected ErrOpen for tampered ct, got %v", err)
	}
	if _, err := aead.Open(nil, nonce, ct, []byte("wrong")); err != ErrOpen {
		t.Errorf("expected ErrOpen for wrong aad, got %v", err)
	}
}

func TestNonceMisuseResistance(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	msg1 := []byte("message one")
	msg2 := []byte("message two")
	ct1 := aead.Seal(nil, nonce, msg1, nil)
	ct1b := aead.Seal(nil, nonce, msg1, nil)
	ct2 := aead.Seal(nil, nonce, msg2, nil)
	if !bytes.Equal(ct1, ct1b) {
		t.Error("same msg + same nonce should yield same ct")
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("different msgs should yield different ct")
	}
}
