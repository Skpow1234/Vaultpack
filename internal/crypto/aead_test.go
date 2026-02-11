package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("hello vaultpack, this is a secret message!")
	key, err := GenerateKey(AES256KeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	result, err := EncryptAESGCM(plaintext, key, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if len(result.Nonce) != GCMNonceSize {
		t.Errorf("nonce size: got %d, want %d", len(result.Nonce), GCMNonceSize)
	}
	if len(result.Tag) != GCMTagSize {
		t.Errorf("tag size: got %d, want %d", len(result.Tag), GCMTagSize)
	}

	decrypted, err := DecryptAESGCM(result.Ciphertext, key, result.Nonce, result.Tag, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted text does not match original")
	}
}

func TestEncryptDecryptWithAAD(t *testing.T) {
	plaintext := []byte("data with AAD")
	key, _ := GenerateKey(AES256KeySize)
	aad := []byte("env=prod,app=payments")

	result, err := EncryptAESGCM(plaintext, key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt with correct AAD.
	decrypted, err := DecryptAESGCM(result.Ciphertext, key, result.Nonce, result.Tag, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted text does not match")
	}

	// Decrypt with wrong AAD should fail.
	_, err = DecryptAESGCM(result.Ciphertext, key, result.Nonce, result.Tag, []byte("wrong-aad"))
	if err == nil {
		t.Fatal("expected error with wrong AAD")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	plaintext := []byte("secret")
	key1, _ := GenerateKey(AES256KeySize)
	key2, _ := GenerateKey(AES256KeySize)

	result, err := EncryptAESGCM(plaintext, key1, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = DecryptAESGCM(result.Ciphertext, key2, result.Nonce, result.Tag, nil)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestEncryptInvalidKeyLength(t *testing.T) {
	_, err := EncryptAESGCM([]byte("data"), []byte("short"), nil)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)
	result, err := EncryptAESGCM([]byte{}, key, nil)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	decrypted, err := DecryptAESGCM(result.Ciphertext, key, result.Nonce, result.Tag, nil)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Error("expected empty plaintext")
	}
}
