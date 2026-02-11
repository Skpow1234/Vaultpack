package crypto

import (
	"bytes"
	"testing"
)

func TestSupportedKDF(t *testing.T) {
	for _, name := range SupportedKDFs {
		if !SupportedKDF(name) {
			t.Errorf("%s should be supported", name)
		}
	}
	if SupportedKDF("bcrypt") {
		t.Error("bcrypt should not be supported")
	}
}

func TestDefaultKDFParams(t *testing.T) {
	for _, algo := range SupportedKDFs {
		params, err := DefaultKDFParams(algo)
		if err != nil {
			t.Fatalf("DefaultKDFParams(%s): %v", algo, err)
		}
		if params.Algo != algo {
			t.Errorf("expected algo %s, got %s", algo, params.Algo)
		}
	}

	_, err := DefaultKDFParams("unknown")
	if err == nil {
		t.Error("expected error for unknown KDF")
	}
}

// TestDeriveKey_AllKDFs verifies key derivation for each supported KDF.
func TestDeriveKey_AllKDFs(t *testing.T) {
	password := []byte("test-password-42!")
	salt := []byte("0123456789abcdef") // 16 bytes

	for _, algo := range SupportedKDFs {
		t.Run(algo, func(t *testing.T) {
			params, _ := DefaultKDFParams(algo)
			params.SaltB64 = "unused" // not used by DeriveKey itself

			// Use smaller params for test speed.
			switch algo {
			case KDFArgon2id:
				params.Time = 1
				params.Memory = 1024 // 1 MB
				params.Threads = 1
			case KDFScrypt:
				params.N = 1024
				params.R = 4
				params.P = 1
			case KDFPBKDF2SHA256:
				params.Iterations = 1000
			}

			key, err := DeriveKey(password, salt, params, 32)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if len(key) != 32 {
				t.Errorf("key length: got %d, want 32", len(key))
			}

			// Verify determinism: same inputs → same key.
			key2, err := DeriveKey(password, salt, params, 32)
			if err != nil {
				t.Fatalf("DeriveKey (2nd call): %v", err)
			}
			if !bytes.Equal(key, key2) {
				t.Error("same inputs produced different keys")
			}
		})
	}
}

// TestDeriveKey_DifferentPasswords verifies that different passwords produce different keys.
func TestDeriveKey_DifferentPasswords(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 1024, Threads: 1}

	key1, _ := DeriveKey([]byte("password-1"), salt, params, 32)
	key2, _ := DeriveKey([]byte("password-2"), salt, params, 32)

	if bytes.Equal(key1, key2) {
		t.Error("different passwords produced same key")
	}
}

// TestDeriveKey_DifferentSalts verifies that different salts produce different keys.
func TestDeriveKey_DifferentSalts(t *testing.T) {
	password := []byte("same-password")
	params := KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 1024, Threads: 1}

	key1, _ := DeriveKey(password, []byte("salt-aaaaaaaaaaaaa"), params, 32)
	key2, _ := DeriveKey(password, []byte("salt-bbbbbbbbbbbbb"), params, 32)

	if bytes.Equal(key1, key2) {
		t.Error("different salts produced same key")
	}
}

// TestDeriveKey_EmptySalt verifies error on empty salt.
func TestDeriveKey_EmptySalt(t *testing.T) {
	params := KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 1024, Threads: 1}
	_, err := DeriveKey([]byte("pass"), nil, params, 32)
	if err == nil {
		t.Error("expected error for empty salt")
	}
}

// TestDeriveKey_ZeroKeyLen verifies error on zero key length.
func TestDeriveKey_ZeroKeyLen(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 1024, Threads: 1}
	_, err := DeriveKey([]byte("pass"), salt, params, 0)
	if err == nil {
		t.Error("expected error for zero key length")
	}
}

// TestDeriveKey_InvalidParams_Argon2id verifies errors for invalid Argon2id parameters.
func TestDeriveKey_InvalidParams_Argon2id(t *testing.T) {
	salt := []byte("0123456789abcdef")

	tests := []struct {
		name   string
		params KDFParams
	}{
		{"zero time", KDFParams{Algo: KDFArgon2id, Time: 0, Memory: 1024, Threads: 1}},
		{"zero memory", KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 0, Threads: 1}},
		{"zero threads", KDFParams{Algo: KDFArgon2id, Time: 1, Memory: 1024, Threads: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey([]byte("pass"), salt, tt.params, 32)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestDeriveKey_InvalidParams_Scrypt verifies errors for invalid scrypt parameters.
func TestDeriveKey_InvalidParams_Scrypt(t *testing.T) {
	salt := []byte("0123456789abcdef")

	tests := []struct {
		name   string
		params KDFParams
	}{
		{"zero N", KDFParams{Algo: KDFScrypt, N: 0, R: 8, P: 1}},
		{"zero R", KDFParams{Algo: KDFScrypt, N: 1024, R: 0, P: 1}},
		{"zero P", KDFParams{Algo: KDFScrypt, N: 1024, R: 8, P: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey([]byte("pass"), salt, tt.params, 32)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestDeriveKey_InvalidParams_PBKDF2 verifies error for zero iterations.
func TestDeriveKey_InvalidParams_PBKDF2(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := KDFParams{Algo: KDFPBKDF2SHA256, Iterations: 0}
	_, err := DeriveKey([]byte("pass"), salt, params, 32)
	if err == nil {
		t.Error("expected error for zero iterations")
	}
}

// TestValidateKDFParams_Valid verifies validation passes for valid params.
func TestValidateKDFParams_Valid(t *testing.T) {
	for _, algo := range SupportedKDFs {
		params, _ := DefaultKDFParams(algo)
		if err := ValidateKDFParams(&params); err != nil {
			t.Errorf("ValidateKDFParams(%s): %v", algo, err)
		}
	}
}

// TestValidateKDFParams_Unsupported verifies validation fails for unsupported algo.
func TestValidateKDFParams_Unsupported(t *testing.T) {
	params := KDFParams{Algo: "bcrypt"}
	if err := ValidateKDFParams(&params); err == nil {
		t.Error("expected error for unsupported algo")
	}
}

// TestGenerateKDFSalt verifies salt generation.
func TestGenerateKDFSalt(t *testing.T) {
	salt, err := GenerateKDFSalt()
	if err != nil {
		t.Fatalf("GenerateKDFSalt: %v", err)
	}
	if len(salt) != KDFSaltSize {
		t.Errorf("salt length: got %d, want %d", len(salt), KDFSaltSize)
	}

	// Two salts should be different.
	salt2, _ := GenerateKDFSalt()
	if bytes.Equal(salt, salt2) {
		t.Error("two generated salts should differ")
	}
}
