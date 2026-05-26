package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptStreamParallel_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("aad")

	sizes := []int{0, 1, 100, DefaultChunkSize - 1, DefaultChunkSize, DefaultChunkSize + 1, 5 * DefaultChunkSize, 10 * DefaultChunkSize}
	ciphers := []string{CipherAES256GCM, CipherChaCha20Poly1305, CipherXChaCha20Poly1305, CipherAES256GCMSIV}

	for _, c := range ciphers {
		for _, sz := range sizes {
			for _, workers := range []int{0, 1, 2, 4, 8} {
				name := c + "/" + itoa(sz) + "B/w=" + itoa(workers)
				t.Run(name, func(t *testing.T) {
					pt := make([]byte, sz)
					rand.Read(pt)

					var ct bytes.Buffer
					res, err := EncryptStreamParallel(bytes.NewReader(pt), &ct, key, aad, DefaultChunkSize, c, workers)
					if err != nil {
						t.Fatalf("EncryptStreamParallel: %v", err)
					}

					var dec bytes.Buffer
					if err := DecryptStream(&ct, &dec, key, res.BaseNonce, aad, DefaultChunkSize, c); err != nil {
						t.Fatalf("DecryptStream: %v", err)
					}
					if !bytes.Equal(dec.Bytes(), pt) {
						t.Errorf("roundtrip mismatch: got %d bytes, want %d", dec.Len(), len(pt))
					}
				})
			}
		}
	}
}

func TestEncryptStreamParallel_MatchesSequential(t *testing.T) {
	// Same chunks should produce same ciphertext when given the same base nonce.
	// We can't share nonces directly, but we can check that decrypting parallel-encrypted
	// output with the sequential decryptor recovers the plaintext (covered above), and
	// that the layout is parseable.
	key := make([]byte, 32)
	rand.Read(key)
	pt := make([]byte, 3*DefaultChunkSize+123)
	rand.Read(pt)

	var ctSeq, ctPar bytes.Buffer
	resSeq, err := EncryptStream(bytes.NewReader(pt), &ctSeq, key, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	resPar, err := EncryptStreamParallel(bytes.NewReader(pt), &ctPar, key, nil, DefaultChunkSize, CipherAES256GCM, 4)
	if err != nil {
		t.Fatal(err)
	}
	if ctSeq.Len() != ctPar.Len() {
		t.Errorf("ciphertext length differs: seq=%d par=%d", ctSeq.Len(), ctPar.Len())
	}
	if resSeq.CiphertextSize != resPar.CiphertextSize {
		t.Errorf("reported size differs: seq=%d par=%d", resSeq.CiphertextSize, resPar.CiphertextSize)
	}
}

func TestDecryptStreamParallel_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("ad")

	sizes := []int{0, 1, DefaultChunkSize, 5 * DefaultChunkSize, 10*DefaultChunkSize + 17}
	ciphers := []string{CipherAES256GCM, CipherChaCha20Poly1305, CipherXChaCha20Poly1305, CipherAES256GCMSIV}
	for _, c := range ciphers {
		for _, sz := range sizes {
			for _, workers := range []int{2, 4} {
				name := "decpar/" + c + "/" + itoa(sz) + "B/w=" + itoa(workers)
				t.Run(name, func(t *testing.T) {
					pt := make([]byte, sz)
					rand.Read(pt)
					var ct bytes.Buffer
					res, err := EncryptStream(bytes.NewReader(pt), &ct, key, aad, DefaultChunkSize, c)
					if err != nil {
						t.Fatal(err)
					}
					var got bytes.Buffer
					if err := DecryptStreamParallel(&ct, &got, key, res.BaseNonce, aad, DefaultChunkSize, c, workers); err != nil {
						t.Fatalf("DecryptStreamParallel: %v", err)
					}
					if !bytes.Equal(got.Bytes(), pt) {
						t.Errorf("roundtrip mismatch")
					}
				})
			}
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
