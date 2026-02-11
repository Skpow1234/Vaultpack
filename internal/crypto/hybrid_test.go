package crypto

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestGenerateHybridKeys_AllSchemes verifies key generation for every hybrid scheme.
func TestGenerateHybridKeys_AllSchemes(t *testing.T) {
	for _, scheme := range SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			privPEM, pubPEM, err := GenerateHybridKeys(scheme)
			if err != nil {
				t.Fatalf("GenerateHybridKeys(%s): %v", scheme, err)
			}
			if len(privPEM) == 0 {
				t.Fatal("empty private key PEM")
			}
			if len(pubPEM) == 0 {
				t.Fatal("empty public key PEM")
			}
		})
	}
}

// TestHybridEncapDecap_AllSchemes tests encapsulation/decapsulation round-trip.
func TestHybridEncapDecap_AllSchemes(t *testing.T) {
	for _, scheme := range SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()
			privPath := filepath.Join(dir, "priv.pem")
			pubPath := filepath.Join(dir, "pub.pem")

			privPEM, pubPEM, err := GenerateHybridKeys(scheme)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			SaveKeyPEM(privPath, privPEM, 0o600)
			SaveKeyPEM(pubPath, pubPEM, 0o644)

			// Encapsulate.
			result, err := HybridEncapsulate(scheme, pubPath)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			if len(result.DEK) != AES256KeySize {
				t.Errorf("DEK size: got %d, want %d", len(result.DEK), AES256KeySize)
			}
			if result.Scheme != scheme {
				t.Errorf("scheme: got %s, want %s", result.Scheme, scheme)
			}

			// Decapsulate.
			dek, err := HybridDecapsulate(scheme, privPath, result.EphemeralPublicKey, result.WrappedDEK)
			if err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if !bytes.Equal(dek, result.DEK) {
				t.Error("decapsulated DEK does not match encapsulated DEK")
			}
		})
	}
}

// TestHybridWrongKeyRejection verifies decapsulation fails with a different private key.
func TestHybridWrongKeyRejection(t *testing.T) {
	for _, scheme := range SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()

			// Generate two key pairs.
			_, pubPEM1, _ := GenerateHybridKeys(scheme)
			pubPath1 := filepath.Join(dir, "pub1.pem")
			SaveKeyPEM(pubPath1, pubPEM1, 0o644)

			privPEM2, _, _ := GenerateHybridKeys(scheme)
			privPath2 := filepath.Join(dir, "priv2.pem")
			SaveKeyPEM(privPath2, privPEM2, 0o600)

			// Encapsulate with pub1.
			result, err := HybridEncapsulate(scheme, pubPath1)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}

			// Try decapsulate with priv2 — should fail.
			dek, err := HybridDecapsulate(scheme, privPath2, result.EphemeralPublicKey, result.WrappedDEK)
			if err == nil && bytes.Equal(dek, result.DEK) {
				t.Error("wrong key produced matching DEK")
			}
			// For ECDH schemes, the DEK will be different (not an error, just wrong).
			// For RSA-OAEP, unwrapping should fail with an error.
		})
	}
}

// TestHybridEphemeralUniqueness verifies two encapsulations produce different ephemeral keys.
func TestHybridEphemeralUniqueness(t *testing.T) {
	ecdhSchemes := []string{HybridX25519AES256GCM, HybridECIESP256}
	for _, scheme := range ecdhSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()
			_, pubPEM, _ := GenerateHybridKeys(scheme)
			pubPath := filepath.Join(dir, "pub.pem")
			SaveKeyPEM(pubPath, pubPEM, 0o644)

			r1, _ := HybridEncapsulate(scheme, pubPath)
			r2, _ := HybridEncapsulate(scheme, pubPath)

			if bytes.Equal(r1.EphemeralPublicKey, r2.EphemeralPublicKey) {
				t.Error("two encapsulations produced identical ephemeral keys")
			}
			if bytes.Equal(r1.DEK, r2.DEK) {
				t.Error("two encapsulations produced identical DEKs")
			}
		})
	}
}

// TestDetectHybridScheme verifies scheme detection from public key.
func TestDetectHybridScheme(t *testing.T) {
	for _, scheme := range SupportedHybridSchemes {
		t.Run(scheme, func(t *testing.T) {
			dir := t.TempDir()
			_, pubPEM, _ := GenerateHybridKeys(scheme)
			pubPath := filepath.Join(dir, "pub.pem")
			SaveKeyPEM(pubPath, pubPEM, 0o644)

			detected, err := DetectHybridScheme(pubPath)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if detected != scheme {
				t.Errorf("detected %s, want %s", detected, scheme)
			}
		})
	}
}

// TestRecipientKeyFingerprint verifies fingerprint generation.
func TestRecipientKeyFingerprint(t *testing.T) {
	dir := t.TempDir()
	_, pubPEM, _ := GenerateHybridKeys(HybridX25519AES256GCM)
	pubPath := filepath.Join(dir, "pub.pem")
	SaveKeyPEM(pubPath, pubPEM, 0o644)

	fp1, err := RecipientKeyFingerprint(pubPath)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if fp1 == "" {
		t.Error("empty fingerprint")
	}

	// Same file → same fingerprint.
	fp2, _ := RecipientKeyFingerprint(pubPath)
	if fp1 != fp2 {
		t.Error("same key produced different fingerprints")
	}
}

// TestSupportedHybridScheme validates the function.
func TestSupportedHybridScheme(t *testing.T) {
	for _, s := range SupportedHybridSchemes {
		if !SupportedHybridScheme(s) {
			t.Errorf("%s should be supported", s)
		}
	}
	if SupportedHybridScheme("rsa-oaep-1024") {
		t.Error("rsa-oaep-1024 should not be supported")
	}
}
