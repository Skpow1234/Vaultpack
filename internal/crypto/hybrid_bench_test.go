package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkKeygen_Ed25519(b *testing.B) {
	dir := b.TempDir()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateSigningKeys(SignAlgoEd25519)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = dir
}

func BenchmarkKeygen_X25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateHybridKeys(HybridX25519AES256GCM)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygen_MLKEM768(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateHybridKeys(HybridMLKEM768)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulate_X25519(b *testing.B) {
	dir := b.TempDir()
	_, pubPEM, err := GenerateHybridKeys(HybridX25519AES256GCM)
	if err != nil {
		b.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HybridEncapsulate(HybridX25519AES256GCM, pubPath)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulate_MLKEM768(b *testing.B) {
	dir := b.TempDir()
	_, pubPEM, err := GenerateHybridKeys(HybridMLKEM768)
	if err != nil {
		b.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HybridEncapsulate(HybridMLKEM768, pubPath)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulateDecapsulate_X25519(b *testing.B) {
	dir := b.TempDir()
	privPEM, pubPEM, err := GenerateHybridKeys(HybridX25519AES256GCM)
	if err != nil {
		b.Fatal(err)
	}
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		b.Fatal(err)
	}
	var result *HybridResult
	result, err = HybridEncapsulate(HybridX25519AES256GCM, pubPath)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HybridDecapsulate(HybridX25519AES256GCM, privPath, result.EphemeralPublicKey, result.WrappedDEK)
		if err != nil {
			b.Fatal(err)
		}
	}
}
