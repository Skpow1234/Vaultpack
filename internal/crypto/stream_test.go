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
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, DefaultChunkSize)
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
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, DefaultChunkSize)
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
	result, err := EncryptStream(bytes.NewReader(nil), &cipherBuf, key, nil, DefaultChunkSize)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, DefaultChunkSize)
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
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, aad, DefaultChunkSize)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Correct AAD.
	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, aad, DefaultChunkSize)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}

	// Wrong AAD.
	var badBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &badBuf, key, result.BaseNonce, []byte("wrong"), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error with wrong AAD")
	}
}

func TestStreamEncryptDecryptWrongKey(t *testing.T) {
	plaintext := []byte("secret")
	key1, _ := GenerateKey(AES256KeySize)
	key2, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, _ := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key1, nil, DefaultChunkSize)

	var plaintextBuf bytes.Buffer
	err := DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key2, result.BaseNonce, nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestStreamMultipleChunks(t *testing.T) {
	// Create data larger than one chunk.
	chunkSize := 1024
	plaintext := make([]byte, chunkSize*3+500) // 3.5 chunks
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Ciphertext should be larger than plaintext (tag overhead per chunk).
	expectedMinSize := int64(len(plaintext) + 4*GCMTagSize) // 4 chunks
	if result.CiphertextSize < expectedMinSize {
		t.Errorf("ciphertext too small: %d < %d", result.CiphertextSize, expectedMinSize)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, chunkSize)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch after multi-chunk roundtrip")
	}
}

func TestStreamExactChunkBoundary(t *testing.T) {
	// Data exactly at chunk boundary.
	chunkSize := 256
	plaintext := make([]byte, chunkSize*2) // exactly 2 chunks
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, chunkSize)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Error("plaintext mismatch at exact chunk boundary")
	}
}

func TestStreamSingleByteChunks(t *testing.T) {
	// Extreme case: 1-byte chunks.
	plaintext := []byte("abcde")
	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, 1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var plaintextBuf bytes.Buffer
	err = DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plaintextBuf, key, result.BaseNonce, nil, 1)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintextBuf.Bytes(), plaintext) {
		t.Errorf("got %q, want %q", plaintextBuf.String(), string(plaintext))
	}
}

func TestStreamTruncationDetection(t *testing.T) {
	// Encrypt multi-chunk data, then truncate the ciphertext.
	chunkSize := 64
	plaintext := make([]byte, chunkSize*3)
	rand.Read(plaintext)

	key, _ := GenerateKey(AES256KeySize)

	var cipherBuf bytes.Buffer
	result, _ := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize)

	// Truncate: remove the last chunk.
	fullCiphertext := cipherBuf.Bytes()
	truncated := fullCiphertext[:len(fullCiphertext)-(chunkSize+GCMTagSize)]

	var plaintextBuf bytes.Buffer
	err := DecryptStream(bytes.NewReader(truncated), &plaintextBuf, key, result.BaseNonce, nil, chunkSize)
	if err == nil {
		t.Fatal("expected error for truncated ciphertext (last-chunk flag mismatch)")
	}
}
