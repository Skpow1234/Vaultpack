package vpackop

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// Decrypt reads a bundle and recovers plaintext.
func Decrypt(p DecryptParams) (*DecryptResult, error) {
	br, err := readBundle(p)
	if err != nil {
		return nil, err
	}
	m := br.Manifest

	if err := validateDecryptModes(p, m); err != nil {
		return nil, err
	}

	key, err := resolveDecryptKey(p, m)
	if err != nil {
		return nil, err
	}

	if m.Encryption.KeyID.Algo != "" && m.Encryption.KeyID.DigestB64 != "" {
		gotAlgo, gotDigest := crypto.KeyFingerprint(key)
		if gotAlgo != m.Encryption.KeyID.Algo || gotDigest != m.Encryption.KeyID.DigestB64 {
			return nil, errors.New("vpackop.Decrypt: key fingerprint mismatch (wrong key)")
		}
	}

	aad := p.AAD
	if aad == nil && m.Encryption.AADB64 != nil && *m.Encryption.AADB64 != "" {
		aad, err = util.B64Decode(*m.Encryption.AADB64)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decode aad: %w", err)
		}
	}

	cipherName := m.Encryption.AEAD
	var plaintext []byte

	if m.Encryption.IsChunked() {
		baseNonce, err := util.B64Decode(m.Encryption.NonceB64)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decode nonce: %w", err)
		}
		chunkSize := crypto.DefaultChunkSize
		if m.Encryption.ChunkSize != nil && *m.Encryption.ChunkSize > 0 {
			chunkSize = *m.Encryption.ChunkSize
		}
		var plaintextBuf bytes.Buffer
		if p.ParallelWorkers > 1 {
			err = crypto.DecryptStreamParallel(
				bytes.NewReader(br.Ciphertext), &plaintextBuf,
				key, baseNonce, aad, chunkSize, cipherName, p.ParallelWorkers,
			)
		} else {
			err = crypto.DecryptStream(
				bytes.NewReader(br.Ciphertext), &plaintextBuf,
				key, baseNonce, aad, chunkSize, cipherName,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decrypt: %w", err)
		}
		plaintext = plaintextBuf.Bytes()
	} else {
		nonce, err := util.B64Decode(m.Encryption.NonceB64)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decode nonce: %w", err)
		}
		tag, err := util.B64Decode(m.Encryption.TagB64)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decode tag: %w", err)
		}
		plaintext, err = crypto.DecryptAEAD(cipherName, br.Ciphertext, key, nonce, tag, aad)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decrypt: %w", err)
		}
	}

	if m.Compress != nil && m.Compress.Algo != "" && m.Compress.Algo != crypto.CompressNone {
		plaintext, err = crypto.Decompress(plaintext, m.Compress.Algo)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: decompress: %w", err)
		}
	}

	result := &DecryptResult{Manifest: m}
	switch {
	case p.OutputPath != "":
		if err := os.WriteFile(p.OutputPath, plaintext, 0o600); err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: write output: %w", err)
		}
	case p.OutputWriter != nil:
		if _, err := p.OutputWriter.Write(plaintext); err != nil {
			return nil, fmt.Errorf("vpackop.Decrypt: write to writer: %w", err)
		}
	default:
		result.Plaintext = plaintext
	}
	return result, nil
}

func readBundle(p DecryptParams) (*bundle.ReadResult, error) {
	switch {
	case p.InputPath != "":
		return bundle.Read(p.InputPath)
	case p.InputBytes != nil:
		return bundle.ReadBytes(p.InputBytes)
	default:
		return nil, errors.New("vpackop.Decrypt: InputPath or InputBytes is required")
	}
}

func validateDecryptModes(p DecryptParams, m *bundle.Manifest) error {
	usePassword := p.Password != ""
	useKey := p.Key != nil
	usePriv := p.PrivateKey != nil || p.PrivateKeyPath != ""
	bundleKMS := m.Encryption.KmsKeyID != "" && m.Encryption.KmsWrappedDEKB64 != ""
	bundleHybrid := m.Encryption.Hybrid != nil
	bundleKDF := m.Encryption.KDF != nil

	modes := 0
	if usePassword {
		modes++
	}
	if useKey {
		modes++
	}
	if usePriv {
		modes++
	}
	if bundleKMS && p.KMSProvider != "" {
		modes++
	}
	if modes > 1 {
		return errors.New("vpackop.Decrypt: Password, Key, PrivateKey, and KMSProvider are mutually exclusive")
	}
	if modes == 0 {
		if bundleKMS {
			return errors.New("vpackop.Decrypt: bundle uses KMS-wrapped DEK; provide KMSProvider")
		}
		if bundleHybrid {
			return errors.New("vpackop.Decrypt: bundle uses hybrid encryption; provide PrivateKey or PrivateKeyPath")
		}
		if bundleKDF {
			return errors.New("vpackop.Decrypt: bundle is password-protected; provide Password")
		}
		return errors.New("vpackop.Decrypt: Key is required")
	}
	if bundleKMS && p.KMSProvider == "" && !usePriv && !usePassword {
		return errors.New("vpackop.Decrypt: bundle uses KMS-wrapped DEK; provide KMSProvider")
	}
	if bundleHybrid && !usePriv {
		return errors.New("vpackop.Decrypt: bundle uses hybrid encryption; provide PrivateKey or PrivateKeyPath")
	}
	if bundleKDF && !usePassword {
		return errors.New("vpackop.Decrypt: bundle is password-protected; provide Password")
	}
	if !bundleKMS && !bundleHybrid && !bundleKDF && !useKey {
		return errors.New("vpackop.Decrypt: Key is required")
	}
	return nil
}

func resolveDecryptKey(p DecryptParams, m *bundle.Manifest) ([]byte, error) {
	if p.PrivateKey != nil || p.PrivateKeyPath != "" {
		return decapsulateHybrid(p, m)
	}
	if m.Encryption.KmsKeyID != "" && m.Encryption.KmsWrappedDEKB64 != "" {
		return unwrapKMS(p, m)
	}
	if p.Password != "" {
		if m.Encryption.KDF == nil {
			return nil, errors.New("vpackop.Decrypt: Password supplied but bundle has no KDF metadata")
		}
		salt, err := util.B64Decode(m.Encryption.KDF.SaltB64)
		if err != nil {
			return nil, err
		}
		params := crypto.KDFParams{
			Algo: m.Encryption.KDF.Algo, SaltB64: m.Encryption.KDF.SaltB64,
			Time: m.Encryption.KDF.Time, Memory: m.Encryption.KDF.Memory,
			Threads: m.Encryption.KDF.Threads, N: m.Encryption.KDF.N,
			R: m.Encryption.KDF.R, P: m.Encryption.KDF.P, Iterations: m.Encryption.KDF.Iterations,
		}
		return crypto.DeriveKey([]byte(p.Password), salt, params, crypto.AES256KeySize)
	}
	if p.Key == nil {
		return nil, errors.New("vpackop.Decrypt: Key is required")
	}
	if len(p.Key) != crypto.AES256KeySize {
		return nil, fmt.Errorf("vpackop.Decrypt: Key must be %d bytes, got %d", crypto.AES256KeySize, len(p.Key))
	}
	return p.Key, nil
}

func unwrapKMS(p DecryptParams, m *bundle.Manifest) ([]byte, error) {
	if p.KMSProvider == "" {
		return nil, errors.New("vpackop.Decrypt: KMSProvider is required")
	}
	wrapped, err := util.B64Decode(m.Encryption.KmsWrappedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("decode KMS-wrapped DEK: %w", err)
	}
	if p.KMSUnwrap != nil {
		return p.KMSUnwrap(wrapped, m.Encryption.KmsKeyID)
	}
	provider := kms.Get(p.KMSProvider)
	if provider == nil {
		return nil, fmt.Errorf("KMS provider %q not found; available: %v", p.KMSProvider, kms.Providers())
	}
	key, err := provider.UnwrapDEK(wrapped, m.Encryption.KmsKeyID)
	if err != nil {
		return nil, fmt.Errorf("KMS unwrap: %w", err)
	}
	return key, nil
}

func decapsulateHybrid(p DecryptParams, m *bundle.Manifest) ([]byte, error) {
	if m.Encryption.Hybrid == nil {
		return nil, errors.New("vpackop.Decrypt: bundle was not encrypted with hybrid encryption")
	}
	path, cleanup, err := pemPath(p.PrivateKey, p.PrivateKeyPath, "vp-priv")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	h := m.Encryption.Hybrid
	if len(h.Recipients) > 0 {
		var decapErr error
		for _, re := range h.Recipients {
			var ephPub, wrappedDEK []byte
			if re.EphemeralPubKeyB64 != "" {
				ephPub, _ = util.B64Decode(re.EphemeralPubKeyB64)
			}
			if re.WrappedDEKB64 != "" {
				wrappedDEK, _ = util.B64Decode(re.WrappedDEKB64)
			}
			var key []byte
			if plugin.GlobalRegistry().KEMScheme(re.Scheme) != "" {
				key, decapErr = plugin.GlobalRegistry().Decapsulate(re.Scheme, path, re.EphemeralPubKeyB64, re.WrappedDEKB64)
			} else {
				key, decapErr = crypto.HybridDecapsulateWrappedDEK(re.Scheme, path, ephPub, wrappedDEK)
			}
			if decapErr == nil {
				return key, nil
			}
		}
		if decapErr != nil {
			return nil, fmt.Errorf("multi-recipient decapsulation failed: %w", decapErr)
		}
		return nil, errors.New("vpackop.Decrypt: no matching recipient found")
	}

	var ephPub, wrappedDEK []byte
	if h.EphemeralPubKeyB64 != "" {
		ephPub, err = util.B64Decode(h.EphemeralPubKeyB64)
		if err != nil {
			return nil, err
		}
	}
	if h.WrappedDEKB64 != "" {
		wrappedDEK, err = util.B64Decode(h.WrappedDEKB64)
		if err != nil {
			return nil, err
		}
	}
	if plugin.GlobalRegistry().KEMScheme(h.Scheme) != "" {
		return plugin.GlobalRegistry().Decapsulate(h.Scheme, path, h.EphemeralPubKeyB64, h.WrappedDEKB64)
	}
	return crypto.HybridDecapsulate(h.Scheme, path, ephPub, wrappedDEK)
}

// CombineShares reconstructs a symmetric key from Shamir shares (the same
// format produced by Protect with SplitShares).
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("vpackop.CombineShares: at least one share is required")
	}
	parsed := make([]*crypto.Share, len(shares))
	for i, raw := range shares {
		s, err := crypto.UnmarshalShare(raw)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i+1, err)
		}
		parsed[i] = s
	}
	secret, err := crypto.CombineShares(parsed)
	if err != nil {
		return nil, err
	}
	// Strip key-file wrapper if present.
	if bytes.HasPrefix(secret, []byte(crypto.KeyFilePrefix)) {
		trimmed := bytes.TrimSpace(bytes.TrimPrefix(secret, []byte(crypto.KeyFilePrefix)))
		key, err := util.B64Decode(string(trimmed))
		if err != nil {
			return nil, fmt.Errorf("decode combined key: %w", err)
		}
		if len(key) != crypto.AES256KeySize {
			return nil, fmt.Errorf("combined key must be %d bytes, got %d", crypto.AES256KeySize, len(key))
		}
		return key, nil
	}
	if len(secret) != crypto.AES256KeySize {
		return nil, fmt.Errorf("combined key must be %d bytes, got %d", crypto.AES256KeySize, len(secret))
	}
	return secret, nil
}
