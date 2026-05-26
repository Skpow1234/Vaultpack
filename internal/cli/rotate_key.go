package cli

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/config"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

// newRotateKeyCmd builds the `vaultpack rotate-key` command.
//
// rotate-key performs a full re-encryption of the payload under a fresh DEK,
// rewraps the new DEK for the same wrapping mode (key file, password, KMS,
// hybrid), and emits a new bundle. Use this when a DEK is suspected of
// compromise, or after removing a recipient, since rewrap/remove-recipient
// alone do not change the underlying ciphertext.
//
// The new manifest invalidates any prior signature; re-sign with 'vaultpack sign'.
func newRotateKeyCmd() *cobra.Command {
	var (
		inFile      string
		outFile     string

		// Old credentials (used to recover the existing DEK).
		oldKeyFile   string
		oldPassword  string
		oldPasswordFile string
		oldPrivKey   string

		// New credentials.
		newKeyOutFile string
		newPassword   string
		newPasswordFile string
		newRecipients []string

		// KMS rotation.
		kmsProvider string
		toKmsKeyID  string

		// Optional overrides.
		cipherName   string
		hashAlgo     string
		kdfAlgo      string
		compressAlgo string
	)

	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Re-encrypt a bundle under a fresh DEK (full rotation)",
		Long: `Re-encrypt a .vpack bundle under a freshly generated Data Encryption Key (DEK).

This is a full rotation: the payload bytes change, the nonce changes, and the
manifest is rebuilt. Use rotate-key when:

  * a DEK is suspected of compromise (full re-encryption is required),
  * you want to revoke a previously-authorized recipient (combine with
    remove-recipient), or
  * you need to migrate the bundle to a different cipher / KDF / KMS key.

The new manifest invalidates any prior signature; re-sign with 'vaultpack sign'.

Provide the OLD credentials so the existing DEK can be unwrapped, plus the new
credentials for the rewrap. The wrapping mode (key file, password, KMS, hybrid)
is preserved from the input unless overridden.`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpRotateKey, inFile, outFile, "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if outFile == "" {
				outFile = inFile
			}

			localIn, cleanup, err := resolveBundlePath(inFile)
			if err != nil {
				return fmt.Errorf("resolve input: %w", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			br, err := bundle.Read(localIn)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			if err := enforcePolicy(audit.OpRotateKey, inFile, br.Manifest); err != nil {
				return err
			}

			// 1) Recover the old DEK from whichever credentials match the bundle's mode.
			oldDEK, mode, err := recoverDEK(br.Manifest, oldKeyFile, oldPassword, oldPasswordFile, oldPrivKey, kmsProvider)
			if err != nil {
				return err
			}

			// 2) Verify the old DEK matches the manifest's KeyID (catch wrong creds early).
			_, oldDigest := crypto.KeyFingerprint(oldDEK)
			if oldDigest != br.Manifest.Encryption.KeyID.DigestB64 {
				return fmt.Errorf("recovered DEK does not match manifest key fingerprint (wrong credentials)")
			}

			// 3) Decrypt the payload with the old DEK.
			plaintext, err := decryptPayloadFromManifest(br, oldDEK)
			if err != nil {
				return fmt.Errorf("decrypt old payload: %w", err)
			}

			// 4) Generate a fresh DEK (rotate-key never reuses the old one).
			newDEK, err := crypto.GenerateKey(crypto.AES256KeySize)
			if err != nil {
				return fmt.Errorf("generate new DEK: %w", err)
			}

			// 5) Build new wrapping metadata for the chosen output mode.
			//    Default: preserve input mode unless the caller has supplied flags for a different mode.
			newKDFMeta, newHybridMeta, newKmsKeyID, newKmsWrapped, err := rewrapNewDEK(
				mode, br.Manifest, newDEK,
				newPassword, newPasswordFile, newRecipients,
				kmsProvider, toKmsKeyID, kdfAlgo,
			)
			if err != nil {
				return fmt.Errorf("rewrap new DEK: %w", err)
			}

			// 6) Apply optional compression & re-encrypt the plaintext under the new DEK.
			if compressAlgo == "" {
				if br.Manifest.Compress != nil {
					compressAlgo = br.Manifest.Compress.Algo
				} else {
					compressAlgo = crypto.CompressNone
				}
			}
			if cipherName == "" {
				cipherName = br.Manifest.Encryption.AEAD
			}
			if hashAlgo == "" {
				hashAlgo = br.Manifest.Plaintext.Algo
			}
			digest, err := crypto.HashReader(bytes.NewReader(plaintext), hashAlgo)
			if err != nil {
				return fmt.Errorf("hash plaintext: %w", err)
			}
			originalSize := int64(len(plaintext))
			var compMeta *bundle.CompressionMeta
			if compressAlgo != crypto.CompressNone {
				compressed, err := crypto.Compress(plaintext, compressAlgo)
				if err != nil {
					return fmt.Errorf("compress: %w", err)
				}
				compMeta = &bundle.CompressionMeta{Algo: compressAlgo, OriginalSize: originalSize}
				plaintext = compressed
			}

			chunkSize := crypto.DefaultChunkSize
			if c := config.Get(); c != nil && c.ChunkSize > 0 {
				chunkSize = c.ChunkSize
			}

			var aad []byte
			if br.Manifest.Encryption.AADB64 != nil {
				aad, _ = util.B64Decode(*br.Manifest.Encryption.AADB64)
			}

			var ciphertextBuf bytes.Buffer
			streamResult, err := crypto.EncryptStream(
				bytes.NewReader(plaintext), &ciphertextBuf,
				newDEK, aad, chunkSize, cipherName,
			)
			if err != nil {
				return fmt.Errorf("re-encrypt: %w", err)
			}

			// 7) Build the new manifest, preserving Input / AEAD / chunk size / AAD.
			newKeyAlgo, newKeyDigest := crypto.KeyFingerprint(newDEK)
			var aadB64 *string
			if aad != nil {
				s := util.B64Encode(aad)
				aadB64 = &s
			}
			encMeta := bundle.EncryptionMeta{
				AEAD:      cipherName,
				NonceB64:  util.B64Encode(streamResult.BaseNonce),
				TagB64:    util.B64Encode(streamResult.LastTag),
				AADB64:    aadB64,
				ChunkSize: &chunkSize,
				KDF:       newKDFMeta,
				Hybrid:    newHybridMeta,
				KeyID: bundle.KeyID{
					Algo:      newKeyAlgo,
					DigestB64: newKeyDigest,
				},
			}
			if newKmsKeyID != "" {
				encMeta.KmsKeyID = newKmsKeyID
				encMeta.KmsWrappedDEKB64 = newKmsWrapped
			}

			newM := &bundle.Manifest{
				Version:   bundle.ManifestVersionV2,
				Input:     br.Manifest.Input,
				Plaintext: bundle.PlaintextHash{Algo: hashAlgo, DigestB64: util.B64Encode(digest)},
				Encryption: encMeta,
				Ciphertext: bundle.CiphertextMeta{Size: streamResult.CiphertextSize},
				Compress:   compMeta,
				// Preserve rotation history from the prior manifest.
				RotatedFrom: append([]bundle.RotationEntry(nil), br.Manifest.RotatedFrom...),
			}

			prevHash, err := hashBundleFile(localIn)
			if err != nil {
				return err
			}
			appendRotation(newM, prevHash, audit.OpRotateKey, fmt.Sprintf("mode=%s cipher=%s", mode, cipherName))

			manifestBytes, err := bundle.MarshalManifest(newM)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}

			// 8) Write bundle (locally then optionally upload).
			localOut := outFile
			remoteOut := ""
			if isRemoteURI(outFile) {
				remoteOut = outFile
				tmp, terr := os.CreateTemp("", "vaultpack-rotate-*.vpack")
				if terr != nil {
					return fmt.Errorf("create temp output: %w", terr)
				}
				tmp.Close()
				localOut = tmp.Name()
				defer os.Remove(tmp.Name())
			}
			if err := bundle.Write(&bundle.WriteParams{
				OutputPath:    localOut,
				Payload:       &ciphertextBuf,
				ManifestBytes: manifestBytes,
			}); err != nil {
				return fmt.Errorf("write bundle: %w", err)
			}
			if remoteOut != "" {
				if err := remoteUploadFile(localOut, remoteOut); err != nil {
					return fmt.Errorf("upload bundle: %w", err)
				}
			}

			// 9) If mode=key-file, emit the new key file (a fresh DEK is useless to the user otherwise).
			if mode == modeKeyFile {
				keyOut := newKeyOutFile
				if keyOut == "" {
					keyOut = outFile + ".key"
				}
				if err := crypto.SaveKeyFile(keyOut, newDEK); err != nil {
					return fmt.Errorf("save new key: %w", err)
				}
				if printer.Mode != OutputJSON {
					printer.Human("New key:   %s", keyOut)
				}
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":           outFile,
					"operation":        audit.OpRotateKey,
					"mode":             mode,
					"new_key_id":       newKeyDigest,
					"old_key_id":       oldDigest,
					"new_cipher":       cipherName,
					"signed":           false,
				})
			default:
				printer.Human("Rotate-key: %s", outFile)
				printer.Human("Mode:       %s", mode)
				printer.Human("Old keyID:  %s", oldDigest)
				printer.Human("New keyID:  %s", newKeyDigest)
				printer.Human("Cipher:     %s", cipherName)
				printer.Human("Signature:  cleared; run 'vaultpack sign' to re-sign.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output bundle path (defaults to --in)")

	cmd.Flags().StringVar(&oldKeyFile, "old-key", "", "old key file (for key-file bundles)")
	cmd.Flags().StringVar(&oldPassword, "old-password", "", "old password (for password bundles)")
	cmd.Flags().StringVar(&oldPasswordFile, "old-password-file", "", "old password file (for password bundles)")
	cmd.Flags().StringVar(&oldPrivKey, "old-privkey", "", "old recipient private key (for hybrid bundles)")
	cmd.Flags().StringVar(&kmsProvider, "kms-provider", "", "KMS provider for KMS bundles (aws|gcp|azure|mock)")

	cmd.Flags().StringVar(&newKeyOutFile, "new-key-out", "", "new key output path (key-file mode; default: <out>.key)")
	cmd.Flags().StringVar(&newPassword, "new-password", "", "new password (password mode)")
	cmd.Flags().StringVar(&newPasswordFile, "new-password-file", "", "new password file (password mode)")
	cmd.Flags().StringArrayVar(&newRecipients, "recipient", nil, "recipient public key for hybrid mode (repeatable, required for hybrid rotation)")
	cmd.Flags().StringVar(&toKmsKeyID, "to-kms-key-id", "", "new KMS key ID (default: reuse manifest's key ID)")

	cmd.Flags().StringVar(&cipherName, "cipher", "", "AEAD cipher (default: preserve from input)")
	cmd.Flags().StringVar(&hashAlgo, "hash", "", "plaintext hash algorithm (default: preserve from input)")
	cmd.Flags().StringVar(&kdfAlgo, "kdf", "", "KDF algorithm for password mode (default: preserve from input)")
	cmd.Flags().StringVar(&compressAlgo, "compress", "", "compression algorithm (default: preserve from input)")

	return cmd
}

// Wrapping modes used by rotate-key.
const (
	modeKeyFile  = "key-file"
	modePassword = "password"
	modeKMS      = "kms"
	modeHybrid   = "hybrid"
)

// recoverDEK figures out the bundle's wrapping mode and returns the old DEK
// plus the mode name.
func recoverDEK(m *bundle.Manifest, oldKey, oldPwd, oldPwdFile, oldPriv, kmsProvider string) ([]byte, string, error) {
	if m.Encryption.Hybrid != nil {
		if oldPriv == "" {
			return nil, "", fmt.Errorf("bundle is hybrid; --old-privkey is required")
		}
		dek, _, err := unwrapHybridDEK(m.Encryption.Hybrid, oldPriv)
		if err != nil {
			return nil, "", err
		}
		return dek, modeHybrid, nil
	}
	if m.Encryption.KmsKeyID != "" && m.Encryption.KmsWrappedDEKB64 != "" {
		if kmsProvider == "" {
			return nil, "", fmt.Errorf("bundle is KMS-wrapped; --kms-provider is required")
		}
		p := kms.Get(kmsProvider)
		if p == nil {
			return nil, "", fmt.Errorf("KMS provider %q not found; available: %v", kmsProvider, kms.Providers())
		}
		wrapped, err := util.B64Decode(m.Encryption.KmsWrappedDEKB64)
		if err != nil {
			return nil, "", fmt.Errorf("decode KMS-wrapped DEK: %w", err)
		}
		dek, err := p.UnwrapDEK(wrapped, m.Encryption.KmsKeyID)
		if err != nil {
			return nil, "", fmt.Errorf("KMS unwrap: %w", err)
		}
		return dek, modeKMS, nil
	}
	if m.Encryption.KDF != nil {
		pwd := oldPwd
		if pwd == "" && oldPwdFile != "" {
			data, err := os.ReadFile(oldPwdFile)
			if err != nil {
				return nil, "", fmt.Errorf("read old password file: %w", err)
			}
			pwd = string(bytes.TrimRight(data, "\r\n"))
		}
		if pwd == "" {
			return nil, "", fmt.Errorf("bundle is password-protected; provide --old-password or --old-password-file")
		}
		salt, err := util.B64Decode(m.Encryption.KDF.SaltB64)
		if err != nil {
			return nil, "", fmt.Errorf("decode KDF salt: %w", err)
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
		dek, err := crypto.DeriveKey([]byte(pwd), salt, params, crypto.AES256KeySize)
		if err != nil {
			return nil, "", fmt.Errorf("derive old key: %w", err)
		}
		return dek, modePassword, nil
	}
	// Default: key file.
	if oldKey == "" {
		return nil, "", fmt.Errorf("bundle is key-file mode; --old-key is required")
	}
	dek, err := crypto.LoadKeyFile(oldKey)
	if err != nil {
		return nil, "", fmt.Errorf("load old key: %w", err)
	}
	return dek, modeKeyFile, nil
}

// decryptPayloadFromManifest decrypts a bundle's payload using the given DEK,
// honoring the manifest's chunked/non-chunked mode and AEAD.
func decryptPayloadFromManifest(br *bundle.ReadResult, dek []byte) ([]byte, error) {
	var aad []byte
	if br.Manifest.Encryption.AADB64 != nil {
		aad, _ = util.B64Decode(*br.Manifest.Encryption.AADB64)
	}
	if br.Manifest.Encryption.IsChunked() {
		baseNonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
		if err != nil {
			return nil, fmt.Errorf("decode nonce: %w", err)
		}
		var buf bytes.Buffer
		if err := crypto.DecryptStream(
			bytes.NewReader(br.Ciphertext), &buf,
			dek, baseNonce, aad,
			*br.Manifest.Encryption.ChunkSize,
			br.Manifest.Encryption.AEAD,
		); err != nil {
			return nil, err
		}
		out := buf.Bytes()
		if br.Manifest.Compress != nil && br.Manifest.Compress.Algo != "" && br.Manifest.Compress.Algo != "none" {
			return crypto.Decompress(out, br.Manifest.Compress.Algo)
		}
		return out, nil
	}
	nonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	tag, err := util.B64Decode(br.Manifest.Encryption.TagB64)
	if err != nil {
		return nil, fmt.Errorf("decode tag: %w", err)
	}
	pt, err := crypto.DecryptAEAD(br.Manifest.Encryption.AEAD, br.Ciphertext, dek, nonce, tag, aad)
	if err != nil {
		return nil, err
	}
	if br.Manifest.Compress != nil && br.Manifest.Compress.Algo != "" && br.Manifest.Compress.Algo != "none" {
		return crypto.Decompress(pt, br.Manifest.Compress.Algo)
	}
	return pt, nil
}

// rewrapNewDEK builds the new manifest's wrapping fields (KDF / Hybrid / KMS)
// for the chosen mode, using the freshly-generated newDEK.
func rewrapNewDEK(
	mode string,
	oldManifest *bundle.Manifest,
	newDEK []byte,
	newPassword, newPasswordFile string,
	newRecipients []string,
	kmsProvider, toKmsKeyID, kdfAlgoOverride string,
) (*bundle.KDFMeta, *bundle.HybridMeta, string, string, error) {
	switch mode {
	case modeKeyFile:
		return nil, nil, "", "", nil

	case modePassword:
		pwd := newPassword
		if pwd == "" && newPasswordFile != "" {
			data, err := os.ReadFile(newPasswordFile)
			if err != nil {
				return nil, nil, "", "", fmt.Errorf("read new password file: %w", err)
			}
			pwd = string(bytes.TrimRight(data, "\r\n"))
		}
		if pwd == "" {
			return nil, nil, "", "", fmt.Errorf("password mode: --new-password or --new-password-file is required")
		}
		algo := kdfAlgoOverride
		if algo == "" {
			algo = oldManifest.Encryption.KDF.Algo
		}
		params, err := crypto.DefaultKDFParams(algo)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("kdf params: %w", err)
		}
		salt, err := crypto.GenerateKey(16)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("generate salt: %w", err)
		}
		params.SaltB64 = util.B64Encode(salt)
		// Overwrite newDEK so its bytes equal the derived key (password mode
		// has no separable DEK / wrapping).
		derived, err := crypto.DeriveKey([]byte(pwd), salt, params, crypto.AES256KeySize)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("derive new key: %w", err)
		}
		copy(newDEK, derived)
		return &bundle.KDFMeta{
			Algo:       params.Algo,
			SaltB64:    params.SaltB64,
			Time:       params.Time,
			Memory:     params.Memory,
			Threads:    params.Threads,
			N:          params.N,
			R:          params.R,
			P:          params.P,
			Iterations: params.Iterations,
		}, nil, "", "", nil

	case modeKMS:
		if kmsProvider == "" {
			return nil, nil, "", "", fmt.Errorf("kms mode: --kms-provider is required")
		}
		p := kms.Get(kmsProvider)
		if p == nil {
			return nil, nil, "", "", fmt.Errorf("KMS provider %q not found", kmsProvider)
		}
		keyID := toKmsKeyID
		if keyID == "" {
			keyID = oldManifest.Encryption.KmsKeyID
		}
		wrapped, err := p.WrapDEK(newDEK, keyID)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("KMS wrap: %w", err)
		}
		return nil, nil, keyID, util.B64Encode(wrapped), nil

	case modeHybrid:
		if len(newRecipients) == 0 {
			return nil, nil, "", "", fmt.Errorf("hybrid mode: at least one --recipient is required (public keys are not stored in the manifest)")
		}
		entries := make([]bundle.RecipientEntry, len(newRecipients))
		var wg sync.WaitGroup
		var firstErr error
		var mu sync.Mutex
		for i, rp := range newRecipients {
			wg.Add(1)
			go func(i int, rp string) {
				defer wg.Done()
				scheme, err := crypto.DetectHybridScheme(rp)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("detect scheme %s: %w", rp, err)
					}
					mu.Unlock()
					return
				}
				fp, err := crypto.RecipientKeyFingerprint(rp)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("fingerprint %s: %w", rp, err)
					}
					mu.Unlock()
					return
				}
				entry := bundle.RecipientEntry{Scheme: scheme, FingerprintB64: fp}
				if plugin.GlobalRegistry().KEMScheme(scheme) != "" {
					pres, err := plugin.GlobalRegistry().Encapsulate(scheme, rp, newDEK)
					if err != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("plugin wrap %s: %w", rp, err)
						}
						mu.Unlock()
						return
					}
					entry.EphemeralPubKeyB64 = pres.EphemeralB64
					entry.WrappedDEKB64 = pres.WrappedDEKB64
				} else {
					res, err := crypto.HybridEncapsulateWithDEK(scheme, rp, newDEK)
					if err != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("wrap %s: %w", rp, err)
						}
						mu.Unlock()
						return
					}
					if len(res.EphemeralPublicKey) > 0 {
						entry.EphemeralPubKeyB64 = util.B64Encode(res.EphemeralPublicKey)
					}
					if len(res.WrappedDEK) > 0 {
						entry.WrappedDEKB64 = util.B64Encode(res.WrappedDEK)
					}
				}
				entries[i] = entry
			}(i, rp)
		}
		wg.Wait()
		if firstErr != nil {
			return nil, nil, "", "", firstErr
		}
		return nil, &bundle.HybridMeta{Scheme: "multi-recipient", Recipients: entries}, "", "", nil

	default:
		return nil, nil, "", "", fmt.Errorf("unknown mode %q", mode)
	}
}
