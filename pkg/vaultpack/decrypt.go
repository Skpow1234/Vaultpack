package vaultpack

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// DecryptOptions controls a single Decrypt call.
//
// Exactly one of {InputPath, InputBytes} must be set. At most one of
// {OutputPath, OutputWriter} may be set; if neither is set, the decrypted
// plaintext is returned in DecryptResult.Plaintext.
//
// Exactly one of {Key, Password} must be set, matching whichever mode was
// used at Protect time. Decrypt cannot guess.
type DecryptOptions struct {
	InputPath  string
	InputBytes []byte

	OutputPath   string
	OutputWriter interface{ Write(p []byte) (int, error) }

	Key      []byte
	Password string

	// AAD is the additional authenticated data the bundle was protected
	// with. Must match exactly, byte-for-byte, or decryption fails.
	AAD []byte
}

// DecryptResult is what Decrypt returns on success.
type DecryptResult struct {
	Manifest *Manifest
	// Plaintext is populated only when neither OutputPath nor OutputWriter
	// was supplied (callers asked for in-memory output).
	Plaintext []byte
}

// Decrypt reads a .vpack bundle and recovers the plaintext, verifying every
// AEAD tag along the way. Returns an error on any tag mismatch, truncation,
// or wrong-key condition.
func Decrypt(opts DecryptOptions) (*DecryptResult, error) {
	if opts.Key == nil && opts.Password == "" {
		return nil, errors.New("vaultpack.Decrypt: Key or Password is required")
	}
	if opts.Key != nil && opts.Password != "" {
		return nil, errors.New("vaultpack.Decrypt: Key and Password are mutually exclusive")
	}

	br, err := readBundle(opts)
	if err != nil {
		return nil, err
	}
	m := br.Manifest

	if m.Encryption.Hybrid != nil {
		return nil, errors.New("vaultpack.Decrypt: hybrid (recipient-based) bundles are not yet supported by the SDK; use the CLI")
	}
	if m.Encryption.KmsKeyID != "" {
		return nil, errors.New("vaultpack.Decrypt: KMS-wrapped bundles are not yet supported by the SDK; use the CLI")
	}
	if m.KeySplitting != nil {
		return nil, errors.New("vaultpack.Decrypt: key-split bundles are not yet supported by the SDK; use the CLI")
	}

	// Resolve the key.
	var key []byte
	switch {
	case opts.Password != "":
		if m.Encryption.KDF == nil {
			return nil, errors.New("vaultpack.Decrypt: Password supplied but bundle has no KDF metadata")
		}
		salt, err := util.B64Decode(m.Encryption.KDF.SaltB64)
		if err != nil {
			return nil, fmt.Errorf("vaultpack.Decrypt: decode salt: %w", err)
		}
		params := crypto.KDFParams{
			Algo:       m.Encryption.KDF.Algo,
			SaltB64:    m.Encryption.KDF.SaltB64,
			Time:       m.Encryption.KDF.Time,
			Memory:     m.Encryption.KDF.Memory,
			Threads:    m.Encryption.KDF.Threads,
			N:          m.Encryption.KDF.N,
			R:          m.Encryption.KDF.R,
			P:          m.Encryption.KDF.P,
			Iterations: m.Encryption.KDF.Iterations,
		}
		key, err = crypto.DeriveKey([]byte(opts.Password), salt, params, crypto.AES256KeySize)
		if err != nil {
			return nil, fmt.Errorf("vaultpack.Decrypt: derive key: %w", err)
		}
	default:
		if len(opts.Key) != crypto.AES256KeySize {
			return nil, fmt.Errorf("vaultpack.Decrypt: Key must be %d bytes, got %d", crypto.AES256KeySize, len(opts.Key))
		}
		key = opts.Key
	}

	// Verify fingerprint when both algo + digest are present in the manifest.
	if m.Encryption.KeyID.Algo != "" && m.Encryption.KeyID.DigestB64 != "" {
		gotAlgo, gotDigest := crypto.KeyFingerprint(key)
		if gotAlgo != m.Encryption.KeyID.Algo || gotDigest != m.Encryption.KeyID.DigestB64 {
			return nil, errors.New("vaultpack.Decrypt: key fingerprint mismatch (wrong key)")
		}
	}

	// Decode nonce + AAD.
	baseNonce, err := util.B64Decode(m.Encryption.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.Decrypt: decode nonce: %w", err)
	}
	aad := opts.AAD
	if aad == nil && m.Encryption.AADB64 != nil && *m.Encryption.AADB64 != "" {
		aad, err = util.B64Decode(*m.Encryption.AADB64)
		if err != nil {
			return nil, fmt.Errorf("vaultpack.Decrypt: decode aad: %w", err)
		}
	}

	chunkSize := crypto.DefaultChunkSize
	if m.Encryption.ChunkSize != nil && *m.Encryption.ChunkSize > 0 {
		chunkSize = *m.Encryption.ChunkSize
	}
	cipherName := m.Encryption.AEAD

	var out bytes.Buffer
	if err := crypto.DecryptStream(
		bytes.NewReader(br.Ciphertext),
		&out,
		key, baseNonce, aad, chunkSize, cipherName,
	); err != nil {
		return nil, fmt.Errorf("vaultpack.Decrypt: decrypt: %w", err)
	}

	result := &DecryptResult{Manifest: m}
	switch {
	case opts.OutputPath != "":
		if err := os.WriteFile(opts.OutputPath, out.Bytes(), 0o600); err != nil {
			return nil, fmt.Errorf("vaultpack.Decrypt: write output: %w", err)
		}
	case opts.OutputWriter != nil:
		if _, err := opts.OutputWriter.Write(out.Bytes()); err != nil {
			return nil, fmt.Errorf("vaultpack.Decrypt: write to writer: %w", err)
		}
	default:
		result.Plaintext = out.Bytes()
	}
	return result, nil
}

func readBundle(opts DecryptOptions) (*bundle.ReadResult, error) {
	switch {
	case opts.InputPath != "":
		return bundle.Read(opts.InputPath)
	case opts.InputBytes != nil:
		return bundle.ReadBytes(opts.InputBytes)
	default:
		return nil, errors.New("vaultpack.Decrypt: InputPath or InputBytes is required")
	}
}
