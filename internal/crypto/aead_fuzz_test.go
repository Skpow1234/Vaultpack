package crypto

import (
	"testing"
)

// FuzzDecryptAESGCM ensures DecryptAESGCM handles arbitrary ciphertext, nonce,
// tag, and AAD without panicking.
func FuzzDecryptAESGCM(f *testing.F) {
	// Generate a valid key and encrypt a known plaintext for the seed corpus.
	key := make([]byte, AES256KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	res, _ := EncryptAESGCM([]byte("hello world"), key, nil)
	if res != nil {
		f.Add(res.Ciphertext, key[:], res.Nonce, res.Tag, []byte{})
	}

	// Seed: all zeros.
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 12), make([]byte, 16), []byte{})

	f.Fuzz(func(t *testing.T, ciphertext, key, nonce, tag, aad []byte) {
		// Must not panic regardless of input.
		_, _ = DecryptAESGCM(ciphertext, key, nonce, tag, aad)
	})
}

// FuzzEncryptDecryptRoundTrip checks that encrypt→decrypt always round-trips
// when given valid parameters.
func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("extra-aad"))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 1024), []byte("large"))

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		key, err := GenerateKey(AES256KeySize)
		if err != nil {
			t.Fatal(err)
		}

		res, err := EncryptAESGCM(plaintext, key, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		got, err := DecryptAESGCM(res.Ciphertext, key, res.Nonce, res.Tag, aad)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}

		if len(plaintext) == 0 && len(got) == 0 {
			return // both empty, OK
		}
		if string(got) != string(plaintext) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	})
}
