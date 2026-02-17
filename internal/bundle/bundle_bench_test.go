package bundle

import (
	"path/filepath"
	"testing"
)

const (
	benchSize1MB   = 1 << 20
	benchSize100MB = 100 << 20
)

func benchManifest(payloadSize int) *Manifest {
	m := validManifest()
	m.Ciphertext.Size = int64(payloadSize)
	return m
}

func BenchmarkWrite_1MB(b *testing.B) {
	dir := b.TempDir()
	m := benchManifest(benchSize1MB)
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext := make([]byte, benchSize1MB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(dir, "out.vpack")
		err := Write(&WriteParams{
			OutputPath:    path,
			Ciphertext:    ciphertext,
			ManifestBytes: manifestBytes,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWrite_100MB(b *testing.B) {
	dir := b.TempDir()
	m := benchManifest(benchSize100MB)
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext := make([]byte, benchSize100MB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(dir, "out.vpack")
		err := Write(&WriteParams{
			OutputPath:    path,
			Ciphertext:    ciphertext,
			ManifestBytes: manifestBytes,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead_1MB(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "read.vpack")
	m := benchManifest(benchSize1MB)
	manifestBytes, _ := MarshalManifest(m)
	ciphertext := make([]byte, benchSize1MB)
	if err := Write(&WriteParams{
		OutputPath: path, Ciphertext: ciphertext, ManifestBytes: manifestBytes,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Read(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead_100MB(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "read.vpack")
	m := benchManifest(benchSize100MB)
	manifestBytes, _ := MarshalManifest(m)
	ciphertext := make([]byte, benchSize100MB)
	if err := Write(&WriteParams{
		OutputPath: path, Ciphertext: ciphertext, ManifestBytes: manifestBytes,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Read(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

