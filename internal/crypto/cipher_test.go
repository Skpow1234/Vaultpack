package crypto

import (
	"testing"
)

func TestSupportedCipher(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{CipherAES256GCM, true},
		{CipherChaCha20Poly1305, true},
		{CipherXChaCha20Poly1305, true},
		{"aes-128-gcm", false},
		{"blowfish", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupportedCipher(tt.name); got != tt.want {
				t.Errorf("SupportedCipher(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestGetCipherInfo(t *testing.T) {
	for _, name := range SupportedCiphers {
		t.Run(name, func(t *testing.T) {
			info, err := GetCipherInfo(name)
			if err != nil {
				t.Fatal(err)
			}
			if info.KeySize != AES256KeySize {
				t.Errorf("key size: got %d, want %d", info.KeySize, AES256KeySize)
			}
			if info.TagSize != GCMTagSize {
				t.Errorf("tag size: got %d, want %d", info.TagSize, GCMTagSize)
			}
			if info.NonceSize < 12 {
				t.Errorf("nonce size too small: %d", info.NonceSize)
			}
		})
	}
}

func TestNewAEAD(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)

	for _, name := range SupportedCiphers {
		t.Run(name, func(t *testing.T) {
			aead, err := NewAEAD(name, key)
			if err != nil {
				t.Fatal(err)
			}

			info, _ := GetCipherInfo(name)
			if aead.NonceSize() != info.NonceSize {
				t.Errorf("AEAD nonce size: got %d, want %d", aead.NonceSize(), info.NonceSize)
			}
			if aead.Overhead() != info.TagSize {
				t.Errorf("AEAD overhead: got %d, want %d", aead.Overhead(), info.TagSize)
			}
		})
	}
}

func TestNewAEAD_WrongKeySize(t *testing.T) {
	badKey := make([]byte, 16) // too short
	for _, name := range SupportedCiphers {
		t.Run(name, func(t *testing.T) {
			_, err := NewAEAD(name, badKey)
			if err == nil {
				t.Fatal("expected error for wrong key size")
			}
		})
	}
}

// TestEncryptDecryptAEAD_AllCiphers verifies non-streaming encrypt/decrypt for each cipher.
func TestEncryptDecryptAEAD_AllCiphers(t *testing.T) {
	for _, name := range SupportedCiphers {
		t.Run(name, func(t *testing.T) {
			key, _ := GenerateKey(AES256KeySize)
			plaintext := []byte("test data for " + name)
			aad := []byte("aad")

			result, err := EncryptAEAD(name, plaintext, key, aad)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			got, err := DecryptAEAD(name, result.Ciphertext, key, result.Nonce, result.Tag, aad)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if string(got) != string(plaintext) {
				t.Errorf("got %q, want %q", got, plaintext)
			}
		})
	}
}

// TestCrossCipherDecryptRejection verifies that ciphertext from one cipher
// cannot be decrypted with a different cipher of the same nonce size.
func TestCrossCipherDecryptRejection(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)
	plaintext := []byte("cross-cipher test")

	// AES-256-GCM and ChaCha20-Poly1305 both use 12-byte nonces.
	result, err := EncryptAEAD(CipherAES256GCM, plaintext, key, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptAEAD(CipherChaCha20Poly1305, result.Ciphertext, key, result.Nonce, result.Tag, nil)
	if err == nil {
		t.Fatal("expected error decrypting AES-GCM ciphertext with ChaCha20-Poly1305")
	}
}
