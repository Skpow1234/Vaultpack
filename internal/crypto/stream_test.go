package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestStreamEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("hello vaultpack streaming encryption!")
	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if len(result.BaseNonce) != GCMNonceSize {
		t.Errorf("base nonce size: %d", len(result.BaseNonce))
	}
	if len(result.LastTag) != GCMTagSize {
		t.Errorf("last tag size: %d", len(result.LastTag))
	}
	if result.CiphertextSize == 0 {
		t.Error("ciphertext size is 0")
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Errorf("got %q, want %q", plaintextBuf.String(), string(plaintext))
	}
}

func TestStreamEncryptDecryptEmpty(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(nil), &cipherBuf, key, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}

	if plaintextBuf.Len() != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", plaintextBuf.Len())
	}
}

func TestStreamEncryptDecryptWithAAD(t *testing.T) {
	plaintext := []byte("data with AAD")
	key, _ := GenerateKey(AES256KeySize)
	aad := []byte("env=prod")

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, aad, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Correct AAD.
	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, aad, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}

	// Wrong AAD.
	var badBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &badBuf, key, result.BaseNonce, []byte("wrong"), DefaultChunkSize, CipherAES256GCM)
	if err == nil {
		t.Fatal("expected error with wrong AAD")
	}
}

func TestStreamEncryptDecryptWrongKey(t *testing.T) {
	plaintext := []byte("secret")
	key1, _ := GenerateKey(AES256KeySize)
	key2, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, _ := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key1, nil, DefaultChunkSize, CipherAES256GCM)

	var plaintextBuf bytes.Buffer
	err := DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key2, result.BaseNonce, nil, DefaultChunkSize, CipherAES256GCM)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestStreamMultipleChunks(t *testing.T) {
	chunkSize := 1024
	plaintext := make([]byte, chunkSize*3+500) // 3.5 chunks
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	expectedMinSize := int64(len(plaintext) + 4*GCMTagSize)
	if result.CiphertextSize < expectedMinSize {
		t.Errorf("ciphertext too small: %d < %d", result.CiphertextSize, expectedMinSize)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, chunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch after multi-chunk roundtrip")
	}
}

func TestStreamExactChunkBoundary(t *testing.T) {
	chunkSize := 256
	plaintext := make([]byte, chunkSize*2)
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, chunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch at exact chunk boundary")
	}
}

func TestStreamSingleByteChunks(t *testing.T) {
	plaintext := []byte("abcde")
	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, 1, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, 1, CipherAES256GCM)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Errorf("got %q, want %q", plaintextBuf.String(), string(plaintext))
	}
}

func TestStreamTruncationDetection(t *testing.T) {
	chunkSize := 64
	plaintext := make([]byte, chunkSize*3)
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, _ := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize, CipherAES256GCM)

	fullCiphertext := cipherBuf.Bytes()
	truncated := fullCiphertext[:len(fullCiphertext)-(chunkSize+GCMTagSize)]

	var plaintextBuf bytes.Buffer
	err := DecryptStream(bytes.NewReader(truncated), &plaintextBuf, key, result.BaseNonce, nil, chunkSize, CipherAES256GCM)
	if err == nil {
		t.Fatal("expected error for truncated ciphertext (last-chunk flag mismatch)")
	}
}

// TestStreamAllCiphersRoundTrip verifies streaming round-trip for each supported cipher.
func TestStreamAllCiphersRoundTrip(t *testing.T) {
	for _, cipherName := range SupportedCiphers {
		t.Run(cipherName, func(t *testing.T) {
			plaintext := []byte("round-trip test for " + cipherName)
			key, _ := GenerateKey(AES256KeySize)

			var cipherBuf bytes.Buffer
			result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, 64, cipherName)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			info, _ := GetCipherInfo(cipherName)
			if len(result.BaseNonce) != info.NonceSize {
				t.Errorf("nonce size: got %d, want %d", len(result.BaseNonce), info.NonceSize)
			}

			var plaintextBuf bytes.Buffer
			err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, 64, cipherName)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
				t.Errorf("got %q, want %q", plaintextBuf.String(), string(plaintext))
			}
		})
	}
}

// TestStreamCrossCipherRejection verifies that ciphertext from one cipher
// cannot be decrypted with a different cipher.
func TestStreamCrossCipherRejection(t *testing.T) {
	plaintext := []byte("cross-cipher rejection test")
	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, DefaultChunkSize, CipherAES256GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Try to decrypt with ChaCha20-Poly1305 — same nonce size, should fail at auth.
	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, DefaultChunkSize, CipherChaCha20Poly1305)
	if err == nil {
		t.Fatal("expected decryption failure with wrong cipher")
	}
}
