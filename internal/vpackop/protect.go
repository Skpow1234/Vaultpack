package vpackop

import (
	"bytes"
	stdcrypto "crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

type stdSigner = stdcrypto.Signer

// Protect encrypts plaintext and writes a .vpack bundle.
func Protect(p ProtectParams) (*ProtectResult, error) {
	plaintextReader, inputName, inputSize, cleanup, err := resolveProtectInput(p)
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if p.OutputPath == "" && p.OutputWriter == nil {
		return nil, errors.New("vpackop.Protect: OutputPath or OutputWriter is required")
	}

	if err := validateProtectModes(p); err != nil {
		return nil, err
	}

	cipherName := p.Cipher
	if cipherName == "" {
		cipherName = crypto.CipherAES256GCM
	}
	if !crypto.SupportedCipher(cipherName) {
		return nil, fmt.Errorf("vpackop.Protect: unsupported cipher %q", cipherName)
	}
	chunkSize := p.ChunkSize
	if chunkSize <= 0 {
		chunkSize = crypto.DefaultChunkSize
	}
	hashAlgo := p.HashAlgo
	if hashAlgo == "" {
		hashAlgo = "sha256"
	}
	if !crypto.SupportedHashAlgo(hashAlgo) {
		return nil, fmt.Errorf("vpackop.Protect: unsupported hash algo %q", hashAlgo)
	}
	if p.Compress != "" && p.Compress != crypto.CompressNone && !crypto.SupportedCompression(p.Compress) {
		return nil, fmt.Errorf("vpackop.Protect: unsupported compression %q", p.Compress)
	}

	var plaintextBuf bytes.Buffer
	hashReader := io.TeeReader(plaintextReader, &plaintextBuf)
	digest, err := crypto.HashReader(hashReader, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("vpackop.Protect: hash plaintext: %w", err)
	}
	if inputSize < 0 {
		inputSize = int64(plaintextBuf.Len())
	}

	key, kdfMeta, hybridMeta, kmsKeyID, kmsWrapped, generated, shares, err := resolveProtectKey(p)
	if err != nil {
		return nil, err
	}

	var compMeta *bundle.CompressionMeta
	if p.Compress != "" && p.Compress != crypto.CompressNone {
		originalSize := int64(plaintextBuf.Len())
		compressed, err := crypto.Compress(plaintextBuf.Bytes(), p.Compress)
		if err != nil {
			return nil, fmt.Errorf("vpackop.Protect: compress: %w", err)
		}
		compMeta = &bundle.CompressionMeta{Algo: p.Compress, OriginalSize: originalSize}
		plaintextBuf.Reset()
		plaintextBuf.Write(compressed)
	}

	var ciphertextBuf bytes.Buffer
	var streamResult *crypto.StreamEncryptResult
	if p.ParallelWorkers > 1 {
		streamResult, err = crypto.EncryptStreamParallel(
			&plaintextBuf, &ciphertextBuf, key, p.AAD, chunkSize, cipherName, p.ParallelWorkers,
		)
	} else {
		streamResult, err = crypto.EncryptStream(
			&plaintextBuf, &ciphertextBuf, key, p.AAD, chunkSize, cipherName,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("vpackop.Protect: encrypt: %w", err)
	}

	keyAlgo, keyDigest := crypto.KeyFingerprint(key)
	var aadB64 *string
	if p.AAD != nil {
		s := util.B64Encode(p.AAD)
		aadB64 = &s
	}

	var splitMeta *bundle.KeySplitMeta
	if p.SplitShares > 0 {
		splitMeta = &bundle.KeySplitMeta{
			Scheme:    "shamir-gf256",
			Threshold: p.SplitThreshold,
			Total:     p.SplitShares,
		}
	}

	manifestVer := bundle.ManifestVersionV1
	if compMeta != nil || (hybridMeta != nil && len(hybridMeta.Recipients) > 0) || splitMeta != nil || kmsKeyID != "" {
		manifestVer = bundle.ManifestVersionV2
	}

	encMeta := bundle.EncryptionMeta{
		AEAD:      cipherName,
		NonceB64:  util.B64Encode(streamResult.BaseNonce),
		TagB64:    util.B64Encode(streamResult.LastTag),
		AADB64:    aadB64,
		ChunkSize: &chunkSize,
		KDF:       kdfMeta,
		Hybrid:    hybridMeta,
		KeyID:     bundle.KeyID{Algo: keyAlgo, DigestB64: keyDigest},
	}
	if kmsKeyID != "" {
		encMeta.KmsKeyID = kmsKeyID
		encMeta.KmsWrappedDEKB64 = kmsWrapped
	}

	m := &bundle.Manifest{
		Version:   manifestVer,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Input:     bundle.InputMeta{Name: inputName, Size: inputSize},
		Plaintext: bundle.PlaintextHash{Algo: hashAlgo, DigestB64: util.B64Encode(digest)},
		Encryption: encMeta,
		Ciphertext: bundle.CiphertextMeta{Size: streamResult.CiphertextSize},
		Compress:     compMeta,
		KeySplitting: splitMeta,
	}

	manifestBytes, err := bundle.MarshalManifest(m)
	if err != nil {
		return nil, fmt.Errorf("vpackop.Protect: marshal manifest: %w", err)
	}

	var sig []byte
	var resolvedSignAlgo string
	if p.Sign != nil {
		sig, resolvedSignAlgo, manifestBytes, err = signManifest(p.Sign, m, &ciphertextBuf)
		if err != nil {
			return nil, err
		}
	}

	wp := &bundle.WriteParams{
		Ciphertext:    ciphertextBuf.Bytes(),
		ManifestBytes: manifestBytes,
		Signature:     sig,
	}
	if p.OutputWriter != nil {
		wp.Writer = p.OutputWriter
	} else {
		wp.OutputPath = p.OutputPath
	}
	if err := bundle.Write(wp); err != nil {
		return nil, fmt.Errorf("vpackop.Protect: write bundle: %w", err)
	}

	res := &ProtectResult{
		Manifest:      m,
		BundlePath:    p.OutputPath,
		SignatureAlgo: resolvedSignAlgo,
		Signature:     sig,
		Shares:        shares,
	}
	if generated && splitMeta == nil {
		res.GeneratedKey = key
	}
	return res, nil
}

func validateProtectModes(p ProtectParams) error {
	usePassword := p.Password != ""
	useRecipient := len(p.Recipients) > 0
	useKMS := p.KMSProvider != "" && p.KMSKeyID != ""
	useKey := p.Key != nil
	useSplit := p.SplitShares > 0 || p.SplitThreshold > 0

	if useKMS && (p.KMSProvider == "" || p.KMSKeyID == "") {
		return errors.New("vpackop.Protect: KMSProvider and KMSKeyID are both required for KMS mode")
	}

	modes := 0
	if usePassword {
		modes++
	}
	if useKey {
		modes++
	}
	if useRecipient {
		modes++
	}
	if useKMS {
		modes++
	}
	if modes > 1 {
		return errors.New("vpackop.Protect: Password, Key, Recipients, and KMS are mutually exclusive")
	}
	if useSplit {
		if p.SplitShares < 2 || p.SplitShares > 255 {
			return errors.New("vpackop.Protect: SplitShares must be in [2..255]")
		}
		if p.SplitThreshold < 2 || p.SplitThreshold > p.SplitShares {
			return errors.New("vpackop.Protect: SplitThreshold must be in [2..SplitShares]")
		}
		if usePassword || useRecipient || useKMS {
			return errors.New("vpackop.Protect: key splitting is only supported with Key or auto-generated key")
		}
	}
	return nil
}

func resolveProtectInput(p ProtectParams) (io.Reader, string, int64, func(), error) {
	switch {
	case p.Plaintext != nil:
		name := p.InputName
		if name == "" {
			name = "memory"
		}
		return bytes.NewReader(p.Plaintext), name, int64(len(p.Plaintext)), nil, nil
	case p.PlaintextReader != nil:
		name := p.InputName
		if name == "" {
			name = "stream"
		}
		return p.PlaintextReader, name, -1, nil, nil
	case p.InputPath != "":
		f, err := os.Open(p.InputPath)
		if err != nil {
			return nil, "", 0, nil, fmt.Errorf("vpackop.Protect: open input: %w", err)
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, "", 0, nil, err
		}
		name := p.InputName
		if name == "" {
			name = filepath.Base(p.InputPath)
		}
		return f, name, info.Size(), func() { f.Close() }, nil
	default:
		return nil, "", 0, nil, errors.New("vpackop.Protect: one of Plaintext / PlaintextReader / InputPath is required")
	}
}

func resolveProtectKey(p ProtectParams) (
	key []byte,
	kdfMeta *bundle.KDFMeta,
	hybridMeta *bundle.HybridMeta,
	kmsKeyID, kmsWrapped string,
	generated bool,
	shares []Share,
	err error,
) {
	switch {
	case len(p.Recipients) > 0:
		key, hybridMeta, err = encapsulateRecipients(p.Recipients)
		return
	case p.KMSProvider != "":
		key, err = crypto.GenerateKey(crypto.AES256KeySize)
		if err != nil {
			return
		}
		provider := kms.Get(p.KMSProvider)
		if provider == nil {
			err = fmt.Errorf("KMS provider %q not found; available: %v", p.KMSProvider, kms.Providers())
			return
		}
		var wrapped []byte
		wrapped, err = provider.WrapDEK(key, p.KMSKeyID)
		if err != nil {
			err = fmt.Errorf("KMS wrap DEK: %w", err)
			return
		}
		kmsKeyID = p.KMSKeyID
		kmsWrapped = util.B64Encode(wrapped)
		return
	case p.Password != "":
		kdfAlgo := p.KDFAlgo
		if kdfAlgo == "" {
			kdfAlgo = crypto.KDFArgon2id
		}
		kdfParams, err2 := crypto.DefaultKDFParams(kdfAlgo)
		if err2 != nil {
			err = err2
			return
		}
		salt, err2 := crypto.GenerateKDFSalt()
		if err2 != nil {
			err = err2
			return
		}
		kdfParams.SaltB64 = util.B64Encode(salt)
		key, err2 = crypto.DeriveKey([]byte(p.Password), salt, kdfParams, crypto.AES256KeySize)
		if err2 != nil {
			err = err2
			return
		}
		kdfMeta = &bundle.KDFMeta{
			Algo: kdfParams.Algo, SaltB64: kdfParams.SaltB64,
			Time: kdfParams.Time, Memory: kdfParams.Memory, Threads: kdfParams.Threads,
			N: kdfParams.N, R: kdfParams.R, P: kdfParams.P, Iterations: kdfParams.Iterations,
		}
		return
	case p.Key != nil:
		if len(p.Key) != crypto.AES256KeySize {
			err = fmt.Errorf("Key must be %d bytes, got %d", crypto.AES256KeySize, len(p.Key))
			return
		}
		key = make([]byte, len(p.Key))
		copy(key, p.Key)
		if p.SplitShares > 0 {
			shares, err = splitKeyMaterial(key, p.SplitShares, p.SplitThreshold)
		}
		return
	default:
		key, err = crypto.GenerateKey(crypto.AES256KeySize)
		if err != nil {
			return
		}
		generated = true
		if p.SplitShares > 0 {
			shares, err = splitKeyMaterial(key, p.SplitShares, p.SplitThreshold)
			generated = false
		}
		return
	}
}

func splitKeyMaterial(key []byte, n, k int) ([]Share, error) {
	keyFileData := []byte(crypto.KeyFilePrefix + util.B64Encode(key) + "\n")
	splitResult, err := crypto.SplitSecret(keyFileData, n, k)
	if err != nil {
		return nil, err
	}
	out := make([]Share, len(splitResult))
	for _, s := range splitResult {
		out[int(s.Index)-1] = Share{Index: int(s.Index), Data: crypto.MarshalShare(s)}
	}
	return out, nil
}

func encapsulateRecipients(recipients []Recipient) ([]byte, *bundle.HybridMeta, error) {
	if len(recipients) == 1 {
		r := recipients[0]
		path, cleanup, err := pemPath(r.PublicKeyPEM, r.PublicKeyPath, "vp-recip")
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()

		scheme, err := crypto.DetectHybridScheme(path)
		if err != nil {
			return nil, nil, err
		}
		if plugin.GlobalRegistry().KEMScheme(scheme) != "" {
			pres, err := plugin.GlobalRegistry().Encapsulate(scheme, path, nil)
			if err != nil {
				return nil, nil, err
			}
			key, err := util.B64Decode(pres.DEKB64)
			if err != nil {
				return nil, nil, err
			}
			fp, err := crypto.RecipientKeyFingerprint(path)
			if err != nil {
				return nil, nil, err
			}
			meta := &bundle.HybridMeta{Scheme: scheme, RecipientFingerprintB64: fp}
			if pres.EphemeralB64 != "" {
				meta.EphemeralPubKeyB64 = pres.EphemeralB64
			}
			if pres.WrappedDEKB64 != "" {
				meta.WrappedDEKB64 = pres.WrappedDEKB64
			}
			return key, meta, nil
		}
		result, err := crypto.HybridEncapsulate(scheme, path)
		if err != nil {
			return nil, nil, err
		}
		fp, err := crypto.RecipientKeyFingerprint(path)
		if err != nil {
			return nil, nil, err
		}
		meta := &bundle.HybridMeta{Scheme: scheme, RecipientFingerprintB64: fp}
		if len(result.EphemeralPublicKey) > 0 {
			meta.EphemeralPubKeyB64 = util.B64Encode(result.EphemeralPublicKey)
		}
		if len(result.WrappedDEK) > 0 {
			meta.WrappedDEKB64 = util.B64Encode(result.WrappedDEK)
		}
		return result.DEK, meta, nil
	}

	key, err := crypto.GenerateKey(crypto.AES256KeySize)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]bundle.RecipientEntry, len(recipients))
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	for i, r := range recipients {
		wg.Add(1)
		go func(i int, r Recipient) {
			defer wg.Done()
			path, cleanup, err := pemPath(r.PublicKeyPEM, r.PublicKeyPath, "vp-recip")
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			defer cleanup()

			scheme, err := crypto.DetectHybridScheme(path)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			var entry bundle.RecipientEntry
			if plugin.GlobalRegistry().KEMScheme(scheme) != "" {
				pres, err := plugin.GlobalRegistry().Encapsulate(scheme, path, key)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				fp, err := crypto.RecipientKeyFingerprint(path)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				entry = bundle.RecipientEntry{Scheme: scheme, FingerprintB64: fp}
				if pres.EphemeralB64 != "" {
					entry.EphemeralPubKeyB64 = pres.EphemeralB64
				}
				if pres.WrappedDEKB64 != "" {
					entry.WrappedDEKB64 = pres.WrappedDEKB64
				}
			} else {
				result, err := crypto.HybridEncapsulateWithDEK(scheme, path, key)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				fp, err := crypto.RecipientKeyFingerprint(path)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				entry = bundle.RecipientEntry{Scheme: scheme, FingerprintB64: fp}
				if len(result.EphemeralPublicKey) > 0 {
					entry.EphemeralPubKeyB64 = util.B64Encode(result.EphemeralPublicKey)
				}
				if len(result.WrappedDEK) > 0 {
					entry.WrappedDEKB64 = util.B64Encode(result.WrappedDEK)
				}
			}
			entries[i] = entry
		}(i, r)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, nil, firstErr
	}
	return key, &bundle.HybridMeta{Scheme: "multi-recipient", Recipients: entries}, nil
}

func signManifest(sp *SignParams, m *bundle.Manifest, ciphertextBuf *bytes.Buffer) ([]byte, string, []byte, error) {
	if sp.PrivateKey == nil && sp.PrivateKeyPath == "" {
		return nil, "", nil, errors.New("vpackop.Protect: Sign requires PrivateKey or PrivateKeyPath")
	}
	var signer stdSigner
	var detected string
	var err error
	if sp.PrivateKeyPath != "" {
		signer, detected, err = crypto.LoadPrivateKey(sp.PrivateKeyPath)
	} else {
		signer, detected, err = crypto.ParsePrivateKey(sp.PrivateKey)
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("vpackop.Protect: load signing key: %w", err)
	}
	algo := detected
	if sp.Algo != "" {
		if sp.Algo != detected {
			return nil, "", nil, fmt.Errorf("vpackop.Protect: Algo %q does not match key type %q", sp.Algo, detected)
		}
		algo = sp.Algo
	}
	m.SignatureAlgo = &algo
	ts := time.Now().UTC().Format(time.RFC3339)
	m.SignedAt = &ts
	canonical, err := bundle.CanonicalManifest(m)
	if err != nil {
		return nil, "", nil, err
	}
	payloadHash, err := crypto.HashReader(bytes.NewReader(ciphertextBuf.Bytes()), "sha256")
	if err != nil {
		return nil, "", nil, err
	}
	sig, err := crypto.SignMessage(signer, algo, crypto.BuildSigningMessage(canonical, payloadHash))
	if err != nil {
		return nil, "", nil, err
	}
	manifestBytes, err := bundle.MarshalManifest(m)
	if err != nil {
		return nil, "", nil, err
	}
	return sig, algo, manifestBytes, nil
}
