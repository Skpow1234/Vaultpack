package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// KDF algorithm names.
const (
	KDFArgon2id    = "argon2id"
	KDFScrypt      = "scrypt"
	KDFPBKDF2SHA256 = "pbkdf2-sha256"
)

// SupportedKDFs is the list of supported KDF names.
var SupportedKDFs = []string{
	KDFArgon2id,
	KDFScrypt,
	KDFPBKDF2SHA256,
}

// SupportedKDF checks whether the given KDF name is supported.
func SupportedKDF(name string) bool {
	for _, k := range SupportedKDFs {
		if k == name {
			return true
		}
	}
	return false
}

// KDFParams holds all parameters needed for key derivation.
type KDFParams struct {
	Algo    string `json:"algo"`
	SaltB64 string `json:"salt_b64"`

	// Argon2id parameters.
	Time    uint32 `json:"time,omitempty"`
	Memory  uint32 `json:"memory,omitempty"`  // KiB
	Threads uint8  `json:"threads,omitempty"`

	// scrypt parameters.
	N int `json:"n,omitempty"` // CPU/memory cost parameter
	R int `json:"r,omitempty"` // block size
	P int `json:"p,omitempty"` // parallelization

	// PBKDF2 parameters.
	Iterations int `json:"iterations,omitempty"`
}

// DefaultArgon2idParams returns the recommended Argon2id parameters.
// t=3, m=64MB (65536 KiB), p=4
func DefaultArgon2idParams() KDFParams {
	return KDFParams{
		Algo:    KDFArgon2id,
		Time:    3,
		Memory:  65536, // 64 MB in KiB
		Threads: 4,
	}
}

// DefaultScryptParams returns the recommended scrypt parameters.
// N=2^15=32768, r=8, p=1
func DefaultScryptParams() KDFParams {
	return KDFParams{
		Algo: KDFScrypt,
		N:    32768,
		R:    8,
		P:    1,
	}
}

// DefaultPBKDF2Params returns the recommended PBKDF2 parameters.
// 600000 iterations (OWASP 2023 recommendation for SHA-256)
func DefaultPBKDF2Params() KDFParams {
	return KDFParams{
		Algo:       KDFPBKDF2SHA256,
		Iterations: 600000,
	}
}

// DefaultKDFParams returns the default parameters for the given KDF name.
func DefaultKDFParams(algo string) (KDFParams, error) {
	switch algo {
	case KDFArgon2id:
		return DefaultArgon2idParams(), nil
	case KDFScrypt:
		return DefaultScryptParams(), nil
	case KDFPBKDF2SHA256:
		return DefaultPBKDF2Params(), nil
	default:
		return KDFParams{}, fmt.Errorf("unsupported KDF %q", algo)
	}
}

// KDFSaltSize is the size of the random salt in bytes.
const KDFSaltSize = 16

// GenerateKDFSalt generates a random 16-byte salt.
func GenerateKDFSalt() ([]byte, error) {
	salt := make([]byte, KDFSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate KDF salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a symmetric key from a password using the specified KDF parameters.
// Returns a key of the given keyLen bytes.
func DeriveKey(password []byte, salt []byte, params KDFParams, keyLen int) ([]byte, error) {
	if len(salt) == 0 {
		return nil, fmt.Errorf("KDF salt is empty")
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("key length must be positive")
	}

	switch params.Algo {
	case KDFArgon2id:
		if params.Time == 0 {
			return nil, fmt.Errorf("argon2id: time must be > 0")
		}
		if params.Memory == 0 {
			return nil, fmt.Errorf("argon2id: memory must be > 0")
		}
		if params.Threads == 0 {
			return nil, fmt.Errorf("argon2id: threads must be > 0")
		}
		key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, uint32(keyLen))
		return key, nil

	case KDFScrypt:
		if params.N <= 0 {
			return nil, fmt.Errorf("scrypt: N must be > 0")
		}
		if params.R <= 0 {
			return nil, fmt.Errorf("scrypt: r must be > 0")
		}
		if params.P <= 0 {
			return nil, fmt.Errorf("scrypt: p must be > 0")
		}
		key, err := scrypt.Key(password, salt, params.N, params.R, params.P, keyLen)
		if err != nil {
			return nil, fmt.Errorf("scrypt: %w", err)
		}
		return key, nil

	case KDFPBKDF2SHA256:
		if params.Iterations <= 0 {
			return nil, fmt.Errorf("pbkdf2: iterations must be > 0")
		}
		key := pbkdf2.Key(password, salt, params.Iterations, keyLen, sha256.New)
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported KDF %q", params.Algo)
	}
}

// ValidateKDFParams checks that a KDFParams struct has valid values.
func ValidateKDFParams(p *KDFParams) error {
	if !SupportedKDF(p.Algo) {
		return fmt.Errorf("unsupported KDF %q", p.Algo)
	}

	switch p.Algo {
	case KDFArgon2id:
		if p.Time == 0 {
			return fmt.Errorf("argon2id: time must be > 0")
		}
		if p.Memory == 0 {
			return fmt.Errorf("argon2id: memory must be > 0")
		}
		if p.Threads == 0 {
			return fmt.Errorf("argon2id: threads must be > 0")
		}
	case KDFScrypt:
		if p.N <= 0 {
			return fmt.Errorf("scrypt: N must be > 0")
		}
		if p.R <= 0 {
			return fmt.Errorf("scrypt: r must be > 0")
		}
		if p.P <= 0 {
			return fmt.Errorf("scrypt: p must be > 0")
		}
	case KDFPBKDF2SHA256:
		if p.Iterations <= 0 {
			return fmt.Errorf("pbkdf2: iterations must be > 0")
		}
	}

	return nil
}
