package crypto

import (
	"bytes"
	"testing"
)

// FuzzStreamEncryptDecryptRoundTrip ensures streaming encrypt→decrypt round-trips
// with arbitrary plaintext and chunk sizes.
func FuzzStreamEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello, streaming world!"), 64, []byte("aad"))
	f.Add([]byte{}, 128, []byte{})
	f.Add(make([]byte, 200), 50, []byte("x"))
	f.Add([]byte("a"), 1, []byte{})

	f.Fuzz(func(t *testing.T, plaintext []byte, chunkSize int, aad []byte) {
		if chunkSize < 1 {
			chunkSize = 1
		}
		if chunkSize > 1<<20 {
			chunkSize = 1 << 20
		}

		key, err := GenerateKey(AES256KeySize)
		if err != nil {
			t.Fatal(err)
		}

		var cipherBuf bytes.Buffer
		result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, aad, chunkSize, CipherAES256GCM)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		var plainBuf bytes.Buffer
		err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plainBuf, key, result.BaseNonce, aad, chunkSize, CipherAES256GCM)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}

		if len(plaintext) == 0 && plainBuf.Len() == 0 {
			return
		}
		if !bytes.Equal(plainBuf.Bytes(), plaintext) {
			t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", plainBuf.Len(), len(plaintext))
		}
	})
}

// FuzzDecryptStreamCorrupted ensures DecryptStream doesn't panic on corrupted data.
func FuzzDecryptStreamCorrupted(f *testing.F) {
	f.Add(make([]byte, 100), make([]byte, 12), make([]byte, 0), 64)
	f.Add([]byte("garbage"), make([]byte, 12), []byte("aad"), 16)

	f.Fuzz(func(t *testing.T, ciphertext, nonce, aad []byte, chunkSize int) {
		if chunkSize < 1 {
			chunkSize = 1
		}
		if chunkSize > 1<<20 {
			chunkSize = 1 << 20
		}

		key := make([]byte, AES256KeySize)
		if len(nonce) != GCMNonceSize {
			nonce = make([]byte, GCMNonceSize)
		}

		var plainBuf bytes.Buffer
		// Must not panic.
		_ = DecryptStream(bytes.NewReader(ciphertext), &plainBuf, key, nonce, aad, chunkSize, CipherAES256GCM)
	})
}
