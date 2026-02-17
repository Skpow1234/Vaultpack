package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newVerifyIntegrityCmd() *cobra.Command {
	var (
		inFile       string
		keyFile      string
		password     string
		passwordFile string
		privKeyFile  string
	)

	cmd := &cobra.Command{
		Use:   "verify-integrity",
		Short: "Decrypt and verify that plaintext hash matches the manifest",
		Long: `Decrypt the .vpack bundle, re-hash the recovered plaintext, and compare it
with the plaintext_hash recorded in the manifest. This confirms end-to-end integrity:
the decrypted content is exactly what was originally protected.

Requires one of --key, --password, or --privkey.`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}

			// Resolve password from file if provided.
			if passwordFile != "" {
				pwData, err := os.ReadFile(passwordFile)
				if err != nil {
					return fmt.Errorf("read password file: %w", err)
				}
				password = strings.TrimRight(string(pwData), "\r\n")
			}

			usePassword := password != ""
			usePrivKey := privKeyFile != ""

			modes := 0
			if usePassword {
				modes++
			}
			if keyFile != "" {
				modes++
			}
			if usePrivKey {
				modes++
			}
			if modes == 0 {
				return fmt.Errorf("one of --key, --password, or --privkey is required")
			}
			if modes > 1 {
				return fmt.Errorf("--password, --key, and --privkey are mutually exclusive")
			}

			// Read bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			// Determine encryption mode.
			bundleUsesKDF := br.Manifest.Encryption.KDF != nil
			bundleUsesHybrid := br.Manifest.Encryption.Hybrid != nil

			// Recover key.
			var key []byte
			if usePrivKey {
				if !bundleUsesHybrid {
					return fmt.Errorf("bundle was not encrypted with hybrid encryption; use --key or --password")
				}
				h := br.Manifest.Encryption.Hybrid
				if len(h.Recipients) > 0 {
					for _, re := range h.Recipients {
						var ephPub, wrappedDEK []byte
						if re.EphemeralPubKeyB64 != "" {
							ephPub, _ = util.B64Decode(re.EphemeralPubKeyB64)
						}
						if re.WrappedDEKB64 != "" {
							wrappedDEK, _ = util.B64Decode(re.WrappedDEKB64)
						}
						if plugin.GlobalRegistry().KEMScheme(re.Scheme) != "" {
							key, err = plugin.GlobalRegistry().Decapsulate(re.Scheme, privKeyFile, re.EphemeralPubKeyB64, re.WrappedDEKB64)
						} else {
							key, err = crypto.HybridDecapsulateWrappedDEK(re.Scheme, privKeyFile, ephPub, wrappedDEK)
						}
						if err == nil {
							break
						}
					}
					if key == nil {
						auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "no matching recipient found")
						printer.Error(util.ErrDecryptFailed, "no matching recipient found")
						os.Exit(util.ExitDecryptFailed)
						return nil
					}
				} else {
					var ephPub, wrappedDEK []byte
					if h.EphemeralPubKeyB64 != "" {
						ephPub, _ = util.B64Decode(h.EphemeralPubKeyB64)
					}
					if h.WrappedDEKB64 != "" {
						wrappedDEK, _ = util.B64Decode(h.WrappedDEKB64)
					}
					if plugin.GlobalRegistry().KEMScheme(h.Scheme) != "" {
						key, err = plugin.GlobalRegistry().Decapsulate(h.Scheme, privKeyFile, h.EphemeralPubKeyB64, h.WrappedDEKB64)
					} else {
						key, err = crypto.HybridDecapsulate(h.Scheme, privKeyFile, ephPub, wrappedDEK)
					}
					if err != nil {
						auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "hybrid decapsulation failed")
						printer.Error(util.ErrDecryptFailed, fmt.Sprintf("hybrid decapsulation failed: %v", err))
						os.Exit(util.ExitDecryptFailed)
						return nil
					}
				}
			} else if usePassword {
				if !bundleUsesKDF {
					return fmt.Errorf("bundle was not encrypted with a password; use --key instead")
				}
				kdfM := br.Manifest.Encryption.KDF
				salt, err := util.B64Decode(kdfM.SaltB64)
				if err != nil {
					return fmt.Errorf("decode KDF salt: %w", err)
				}
				kdfParams := crypto.KDFParams{
					Algo:       kdfM.Algo,
					SaltB64:    kdfM.SaltB64,
					Time:       kdfM.Time,
					Memory:     kdfM.Memory,
					Threads:    kdfM.Threads,
					N:          kdfM.N,
					R:          kdfM.R,
					P:          kdfM.P,
					Iterations: kdfM.Iterations,
				}
				key, err = crypto.DeriveKey([]byte(password), salt, kdfParams, crypto.AES256KeySize)
				if err != nil {
					return fmt.Errorf("derive key: %w", err)
				}
			} else {
				key, err = crypto.LoadKeyFile(keyFile)
				if err != nil {
					return fmt.Errorf("load key: %w", err)
				}
			}

			// Verify key fingerprint.
			_, keyDigest := crypto.KeyFingerprint(key)
			if keyDigest != br.Manifest.Encryption.KeyID.DigestB64 {
				auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "key fingerprint mismatch")
				if usePassword {
					printer.Error(util.ErrDecryptFailed, "wrong password (key fingerprint mismatch)")
				} else {
					printer.Error(util.ErrKeyMismatch, "key fingerprint does not match manifest")
				}
				os.Exit(util.ExitDecryptFailed)
				return nil
			}

			// Decode AAD.
			var aad []byte
			if br.Manifest.Encryption.AADB64 != nil {
				aad, err = util.B64Decode(*br.Manifest.Encryption.AADB64)
				if err != nil {
					return fmt.Errorf("decode aad: %w", err)
				}
			}

			// Decrypt.
			cipherName := br.Manifest.Encryption.AEAD
			var plaintext []byte

			if br.Manifest.Encryption.IsChunked() {
				baseNonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
				if err != nil {
					return fmt.Errorf("decode nonce: %w", err)
				}
				var buf bytes.Buffer
				err = crypto.DecryptStream(
					bytes.NewReader(br.Ciphertext),
					&buf,
					key, baseNonce, aad,
					*br.Manifest.Encryption.ChunkSize,
					cipherName,
				)
				if err != nil {
					auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "decryption failed")
					printer.Error(err, "decryption failed")
					os.Exit(util.ExitDecryptFailed)
					return nil
				}
				plaintext = buf.Bytes()
			} else {
				nonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
				if err != nil {
					return fmt.Errorf("decode nonce: %w", err)
				}
				tag, err := util.B64Decode(br.Manifest.Encryption.TagB64)
				if err != nil {
					return fmt.Errorf("decode tag: %w", err)
				}
				plaintext, err = crypto.DecryptAEAD(cipherName, br.Ciphertext, key, nonce, tag, aad)
				if err != nil {
					auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "decryption failed")
					printer.Error(err, "decryption failed")
					os.Exit(util.ExitDecryptFailed)
					return nil
				}
			}

			// Decompress if needed.
			if br.Manifest.Compress != nil && br.Manifest.Compress.Algo != "" && br.Manifest.Compress.Algo != "none" {
				plaintext, err = crypto.Decompress(plaintext, br.Manifest.Compress.Algo)
				if err != nil {
					return fmt.Errorf("decompress: %w", err)
				}
			}

			// Re-hash the plaintext.
			hashAlgo := br.Manifest.Plaintext.Algo
			digest, err := crypto.HashReader(bytes.NewReader(plaintext), hashAlgo)
			if err != nil {
				return fmt.Errorf("re-hash plaintext: %w", err)
			}

			digestB64 := util.B64Encode(digest)
			match := digestB64 == br.Manifest.Plaintext.DigestB64

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":          inFile,
					"integrity_valid": match,
					"hash_algo":       hashAlgo,
					"expected_hash":   br.Manifest.Plaintext.DigestB64,
					"actual_hash":     digestB64,
				})
			default:
				if match {
					printer.Human("Integrity: PASS")
					printer.Human("Bundle:    %s", inFile)
					printer.Human("Hash:      %s:%s", hashAlgo, digestB64)
				} else {
					printer.Human("Integrity: FAIL")
					printer.Human("Bundle:    %s", inFile)
					printer.Human("Expected:  %s:%s", hashAlgo, br.Manifest.Plaintext.DigestB64)
					printer.Human("Actual:    %s:%s", hashAlgo, digestB64)
				}
			}

			if !match {
				auditLog(audit.OpVerifyIntegrity, inFile, "", "", "", false, "plaintext hash mismatch")
				os.Exit(util.ExitVerifyFailed)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&keyFile, "key", "", "decryption key file")
	cmd.Flags().StringVar(&password, "password", "", "password for password-protected bundles")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "read password from file")
	cmd.Flags().StringVar(&privKeyFile, "privkey", "", "private key for hybrid-encrypted bundles (PEM)")

	return cmd
}
