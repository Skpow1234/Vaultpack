package bundle

import (
	"testing"
)

// FuzzUnmarshalManifest feeds random bytes into UnmarshalManifest → ValidateManifest.
// Goal: ensure no panics, only controlled errors.
func FuzzUnmarshalManifest(f *testing.F) {
	// Seed corpus with a valid manifest JSON.
	f.Add([]byte(`{
  "version": "v1",
  "created_at": "2025-01-01T00:00:00Z",
  "input": {"name": "test.csv", "size": 42},
  "plaintext_hash": {"algo": "sha256", "digest_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
  "encryption": {
    "aead": "aes-256-gcm",
    "nonce_b64": "AAAAAAAAAAAAAAA=",
    "tag_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
    "key_id": {"algo": "sha256", "digest_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
  },
  "ciphertext": {"size": 58}
}`))

	// Seed: empty JSON object.
	f.Add([]byte(`{}`))

	// Seed: completely invalid JSON.
	f.Add([]byte(`not json at all`))

	// Seed: valid JSON but wrong types.
	f.Add([]byte(`{"version": 123}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalManifest(data)
		if err != nil {
			return // JSON parse error — expected for most random input.
		}
		// If parsing succeeded, validate must not panic.
		_ = ValidateManifest(m)
	})
}

// FuzzCanonicalManifest ensures CanonicalManifest doesn't panic on arbitrary Manifest structs.
func FuzzCanonicalManifest(f *testing.F) {
	f.Add("v1", "2025-01-01T00:00:00Z", "test.csv", "sha256", "aes-256-gcm")
	f.Add("v1", "2025-01-01T00:00:00Z", "data.bin", "sha512", "aes-256-gcm")
	f.Add("v1", "2025-01-01T00:00:00Z", "data.bin", "sha3-256", "aes-256-gcm")
	f.Add("v1", "2025-01-01T00:00:00Z", "data.bin", "blake2b-256", "aes-256-gcm")
	f.Add("v1", "2025-01-01T00:00:00Z", "data.bin", "blake3", "aes-256-gcm")
	f.Add("", "", "", "", "")
	f.Add("v2", "bogus", "\x00\xff", "md5", "chacha20")

	f.Fuzz(func(t *testing.T, version, createdAt, inputName, hashAlgo, aead string) {
		m := &Manifest{
			Version:   version,
			CreatedAt: createdAt,
			Input:     InputMeta{Name: inputName, Size: 0},
			Plaintext: PlaintextHash{Algo: hashAlgo, DigestB64: "AA=="},
			Encryption: EncryptionMeta{
				AEAD:     aead,
				NonceB64: "AAAAAAAAAAAAAAA=",
				TagB64:   "AAAAAAAAAAAAAAAAAAAAAA==",
				KeyID:    KeyID{Algo: "sha256", DigestB64: "AA=="},
			},
			Ciphertext: CiphertextMeta{Size: 0},
		}

		data, err := MarshalManifest(m)
		if err != nil {
			return
		}

		// Round-trip: unmarshal and validate must not panic.
		m2, err := UnmarshalManifest(data)
		if err != nil {
			return
		}
		_ = ValidateManifest(m2)

		// Canonical must not panic.
		_, _ = CanonicalManifest(m)
	})
}
