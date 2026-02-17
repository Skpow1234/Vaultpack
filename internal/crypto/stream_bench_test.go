package crypto

import (
	"bytes"
	"io"
	"testing"
)

const (
	size1MB  = 1 << 20
	size100MB = 100 << 20
)

func BenchmarkEncryptStream_1MB(b *testing.B) {
	key := make([]byte, AES256KeySize)
	plaintext := make([]byte, size1MB)
	encryptStreamBench(b, key, plaintext, DefaultChunkSize, CipherAES256GCM)
}

func BenchmarkEncryptStream_100MB(b *testing.B) {
	key := make([]byte, AES256KeySize)
	plaintext := make([]byte, size100MB)
	encryptStreamBench(b, key, plaintext, DefaultChunkSize, CipherAES256GCM)
}

func BenchmarkEncryptStream_1MB_ChaCha20(b *testing.B) {
	key := make([]byte, AES256KeySize)
	plaintext := make([]byte, size1MB)
	encryptStreamBench(b, key, plaintext, DefaultChunkSize, CipherChaCha20Poly1305)
}

func encryptStreamBench(b *testing.B, key, plaintext []byte, chunkSize int, cipher string) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := EncryptStream(
			bytes.NewReader(plaintext),
			io.Discard,
			key, nil, chunkSize, cipher,
		)
		if err != nil {
			b.Fatal(err)
		}
		_ = result
	}
}

func BenchmarkDecryptStream_1MB(b *testing.B) {
	key := make([]byte, AES256KeySize)
	plaintext := make([]byte, size1MB)
	decryptStreamBench(b, key, plaintext, DefaultChunkSize)
}

func BenchmarkDecryptStream_100MB(b *testing.B) {
	key := make([]byte, AES256KeySize)
	plaintext := make([]byte, size100MB)
	decryptStreamBench(b, key, plaintext, DefaultChunkSize)
}

func decryptStreamBench(b *testing.B, key, plaintext []byte, chunkSize int) {
	var cipherBuf bytes.Buffer
	result, err := EncryptStream(bytes.NewReader(plaintext), &cipherBuf, key, nil, chunkSize, CipherAES256GCM)
	if err != nil {
		b.Fatal(err)
	}
	cipherBytes := cipherBuf.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := DecryptStream(
			bytes.NewReader(cipherBytes),
			io.Discard,
			key, result.BaseNonce, nil, chunkSize, CipherAES256GCM,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

