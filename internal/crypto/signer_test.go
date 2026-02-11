package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateSigningKeys_AllAlgos verifies key generation for every supported algorithm.
func TestGenerateSigningKeys_AllAlgos(t *testing.T) {
	for _, algo := range SupportedSignAlgos {
		t.Run(algo, func(t *testing.T) {
			privPEM, pubPEM, err := GenerateSigningKeys(algo)
			if err != nil {
				t.Fatalf("GenerateSigningKeys(%s): %v", algo, err)
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

// TestSignVerifyRoundTrip_AllAlgos performs sign-verify round-trip for each algorithm.
func TestSignVerifyRoundTrip_AllAlgos(t *testing.T) {
	for _, algo := range SupportedSignAlgos {
		t.Run(algo, func(t *testing.T) {
			privPEM, pubPEM, err := GenerateSigningKeys(algo)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}

			// Save and reload keys via PEM files.
			dir := t.TempDir()
			privPath := filepath.Join(dir, "priv.pem")
			pubPath := filepath.Join(dir, "pub.pem")

			if err := SaveKeyPEM(privPath, privPEM, 0o600); err != nil {
				t.Fatalf("save priv: %v", err)
			}
			if err := SaveKeyPEM(pubPath, pubPEM, 0o644); err != nil {
				t.Fatalf("save pub: %v", err)
			}

			signer, detectedAlgo, err := LoadPrivateKey(privPath)
			if err != nil {
				t.Fatalf("LoadPrivateKey: %v", err)
			}
			if detectedAlgo != algo {
				t.Errorf("detected algo %s, want %s", detectedAlgo, algo)
			}

			pubKey, pubAlgo, err := LoadAnyPublicKey(pubPath)
			if err != nil {
				t.Fatalf("LoadAnyPublicKey: %v", err)
			}
			if pubAlgo != algo {
				t.Errorf("detected pub algo %s, want %s", pubAlgo, algo)
			}

			// Sign and verify.
			message := []byte("round-trip message for " + algo)
			sig, err := SignMessage(signer, algo, message)
			if err != nil {
				t.Fatalf("SignMessage: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("empty signature")
			}

			valid, err := VerifySignature(pubKey, algo, message, sig)
			if err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
			if !valid {
				t.Error("signature should be valid")
			}
		})
	}
}

// TestCrossAlgoRejection ensures a signature created with one algorithm
// cannot be verified with a key from a different algorithm.
func TestCrossAlgoRejection(t *testing.T) {
	type keyPair struct {
		algo string
		priv string
		pub  string
	}

	dir := t.TempDir()
	pairs := make([]keyPair, 0, len(SupportedSignAlgos))

	for _, algo := range SupportedSignAlgos {
		privPEM, pubPEM, err := GenerateSigningKeys(algo)
		if err != nil {
			t.Fatalf("keygen %s: %v", algo, err)
		}
		privPath := filepath.Join(dir, algo+".priv.pem")
		pubPath := filepath.Join(dir, algo+".pub.pem")
		SaveKeyPEM(privPath, privPEM, 0o600)
		SaveKeyPEM(pubPath, pubPEM, 0o644)
		pairs = append(pairs, keyPair{algo: algo, priv: privPath, pub: pubPath})
	}

	message := []byte("cross-algo test message")

	for _, signer := range pairs {
		privKey, signerAlgo, _ := LoadPrivateKey(signer.priv)
		sig, err := SignMessage(privKey, signerAlgo, message)
		if err != nil {
			t.Fatalf("sign with %s: %v", signer.algo, err)
		}

		for _, verifier := range pairs {
			if verifier.algo == signer.algo {
				continue // same algo, skip
			}
			pubKey, verifierAlgo, _ := LoadAnyPublicKey(verifier.pub)

			// This should either fail or return false.
			valid, err := VerifySignature(pubKey, verifierAlgo, message, sig)
			if valid && err == nil {
				t.Errorf("cross-algo: signed with %s verified with %s; expected rejection",
					signer.algo, verifier.algo)
			}
		}
	}
}

// TestTamperDetection verifies that flipping one byte in the message
// causes verification to fail.
func TestTamperDetection(t *testing.T) {
	for _, algo := range SupportedSignAlgos {
		t.Run(algo, func(t *testing.T) {
			privPEM, pubPEM, err := GenerateSigningKeys(algo)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}

			dir := t.TempDir()
			privPath := filepath.Join(dir, "priv.pem")
			pubPath := filepath.Join(dir, "pub.pem")
			SaveKeyPEM(privPath, privPEM, 0o600)
			SaveKeyPEM(pubPath, pubPEM, 0o644)

			signer, signerAlgo, _ := LoadPrivateKey(privPath)
			pubKey, pubAlgo, _ := LoadAnyPublicKey(pubPath)

			message := []byte("original message for tamper test")
			sig, err := SignMessage(signer, signerAlgo, message)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			// Flip one byte in the message.
			tampered := make([]byte, len(message))
			copy(tampered, message)
			tampered[0] ^= 0xFF

			valid, err := VerifySignature(pubKey, pubAlgo, tampered, sig)
			if err != nil {
				// Some algos may return an error instead of false.
				return
			}
			if valid {
				t.Error("tampered message verified; expected failure")
			}
		})
	}
}

// TestLegacyEd25519Keys verifies backward compatibility with legacy raw format.
func TestLegacyEd25519Keys(t *testing.T) {
	// Generate keys using the old format functions (still present in sign.go).
	priv, pub, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("generate legacy keys: %v", err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "legacy.key")
	pubPath := filepath.Join(dir, "legacy.pub")

	if err := SaveSigningKey(privPath, priv); err != nil {
		t.Fatalf("save legacy priv: %v", err)
	}
	if err := SavePublicKey(pubPath, pub); err != nil {
		t.Fatalf("save legacy pub: %v", err)
	}

	// Load with new API.
	loadedPriv, algo, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey legacy: %v", err)
	}
	if algo != SignAlgoEd25519 {
		t.Errorf("expected ed25519, got %s", algo)
	}

	loadedPub, pubAlgo, err := LoadAnyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadAnyPublicKey legacy: %v", err)
	}
	if pubAlgo != SignAlgoEd25519 {
		t.Errorf("expected ed25519, got %s", pubAlgo)
	}

	// Sign with new API, verify with new API.
	msg := []byte("legacy compatibility test")
	sig, err := SignMessage(loadedPriv, algo, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := VerifySignature(loadedPub, pubAlgo, msg, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("legacy keys should work with new API")
	}
}

// TestSupportedSignAlgo validates the SupportedSignAlgo function.
func TestSupportedSignAlgo(t *testing.T) {
	for _, algo := range SupportedSignAlgos {
		if !SupportedSignAlgo(algo) {
			t.Errorf("%s should be supported", algo)
		}
	}
	if SupportedSignAlgo("dsa") {
		t.Error("dsa should not be supported")
	}
}

// TestGenerateSigningKeys_Unsupported verifies error for unknown algo.
func TestGenerateSigningKeys_Unsupported(t *testing.T) {
	_, _, err := GenerateSigningKeys("unknown-algo")
	if err == nil {
		t.Error("expected error for unsupported algo")
	}
}

// TestSaveLoadKeyPEM_RoundTrip verifies PEM save/load round-trip.
func TestSaveLoadKeyPEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	data := []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
	path := filepath.Join(dir, "test.pem")

	if err := SaveKeyPEM(path, data, 0o600); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(loaded) != string(data) {
		t.Error("round-trip mismatch")
	}
}
