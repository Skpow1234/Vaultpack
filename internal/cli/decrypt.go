package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/config"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	var (
		inFile       string
		outFile      string
		keyFile      string
		aadStr       string
		useStdout    bool
		password     string
		passwordFile string
		privKeyFile  string
		kmsProvider  string
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a .vpack bundle",
		Long:  "Read a .vpack bundle, decrypt the payload using the provided key, and write the plaintext.\n\nAzure: use az://container/blob paths for --in and/or --out.\n\nUse --stdout to write decrypted plaintext to standard output.",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			auditInFile := inFile
			var auditOutDesc, auditKeyFP string
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpDecrypt, auditInFile, auditOutDesc, "", auditKeyFP, err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if outFile == "" && !useStdout {
				return fmt.Errorf("--out or --stdout is required")
			}

			// Azure: download input bundle from blob if az:// URI.
			var azInputCleanup func()
			if isAzure(inFile) {
				tmpPath, err := azureDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from Azure: %w", err)
				}
				azInputCleanup = func() { os.Remove(tmpPath) }
				inFile = tmpPath
			}
			defer func() {
				if azInputCleanup != nil {
					azInputCleanup()
				}
			}()

			// Track whether the output should be uploaded to Azure.
			azOutURI := ""
			if isAzure(outFile) {
				azOutURI = outFile
			}

			// When writing to stdout, redirect printer to stderr.
			if useStdout {
				printer.Writer = os.Stderr
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

			// Read bundle early to check for KMS (affects mode count).
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			bundleUsesKMS := br.Manifest.Encryption.KmsKeyID != "" && br.Manifest.Encryption.KmsWrappedDEKB64 != ""
			if bundleUsesKMS && kmsProvider == "" && config.Get() != nil && config.Get().KmsProvider != "" {
				kmsProvider = config.Get().KmsProvider
			}
			useKMS := bundleUsesKMS && kmsProvider != ""

			// Mutual exclusivity.
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
			if useKMS {
				modes++
			}
			if modes > 1 {
				return fmt.Errorf("--password, --key, --privkey, and --kms-provider are mutually exclusive")
			}

			// Determine encryption mode from manifest.
			bundleUsesKDF := br.Manifest.Encryption.KDF != nil
			bundleUsesHybrid := br.Manifest.Encryption.Hybrid != nil

			// Guide user to the right flag.
			if modes == 0 {
				if bundleUsesKMS {
					return fmt.Errorf("this bundle uses KMS-wrapped DEK; provide --kms-provider (e.g. aws or mock)")
				}
				if bundleUsesHybrid {
					return fmt.Errorf("this bundle uses hybrid encryption; provide --privkey <your-private-key.pem>")
				}
				if bundleUsesKDF {
					return fmt.Errorf("this bundle is password-protected; provide --password or --password-file")
				}
				return fmt.Errorf("--key is required (or --password / --privkey / --kms-provider)")
			}

			// Load, derive, or decapsulate key.
			var key []byte
			if usePrivKey {
				if !bundleUsesHybrid {
					return fmt.Errorf("bundle was not encrypted with hybrid encryption; use --key or --password")
				}
				h := br.Manifest.Encryption.Hybrid

				if len(h.Recipients) > 0 {
					// Multi-recipient: try to find a matching recipient entry.
					var decapErr error
					for _, re := range h.Recipients {
						var ephPub, wrappedDEK []byte
						if re.EphemeralPubKeyB64 != "" {
							ephPub, err = util.B64Decode(re.EphemeralPubKeyB64)
							if err != nil {
								continue
							}
						}
						if re.WrappedDEKB64 != "" {
							wrappedDEK, err = util.B64Decode(re.WrappedDEKB64)
							if err != nil {
								continue
							}
						}
						key, decapErr = crypto.HybridDecapsulateWrappedDEK(re.Scheme, privKeyFile, ephPub, wrappedDEK)
						if decapErr == nil {
							break
						}
					}
					if key == nil {
						msg := "no matching recipient found"
						if decapErr != nil {
							msg = fmt.Sprintf("multi-recipient decapsulation failed: %v", decapErr)
						}
						printer.Error(util.ErrDecryptFailed, msg)
						os.Exit(util.ExitDecryptFailed)
						return nil
					}
				} else {
					// Single-recipient.
					var ephPub, wrappedDEK []byte
					if h.EphemeralPubKeyB64 != "" {
						ephPub, err = util.B64Decode(h.EphemeralPubKeyB64)
						if err != nil {
							return fmt.Errorf("decode ephemeral public key: %w", err)
						}
					}
					if h.WrappedDEKB64 != "" {
						wrappedDEK, err = util.B64Decode(h.WrappedDEKB64)
						if err != nil {
							return fmt.Errorf("decode wrapped DEK: %w", err)
						}
					}
					key, err = crypto.HybridDecapsulate(h.Scheme, privKeyFile, ephPub, wrappedDEK)
					if err != nil {
						printer.Error(util.ErrDecryptFailed, fmt.Sprintf("hybrid decapsulation failed: %v", err))
						os.Exit(util.ExitDecryptFailed)
						return nil
					}
				}
			} else if useKMS {
				wrapped, err := util.B64Decode(br.Manifest.Encryption.KmsWrappedDEKB64)
				if err != nil {
					return fmt.Errorf("decode KMS-wrapped DEK: %w", err)
				}
				provider := kms.Get(kmsProvider)
				if provider == nil {
					return fmt.Errorf("KMS provider %q not found; available: %v", kmsProvider, kms.Providers())
				}
				key, err = provider.UnwrapDEK(wrapped, br.Manifest.Encryption.KmsKeyID)
				if err != nil {
					printer.Error(util.ErrDecryptFailed, fmt.Sprintf("KMS unwrap failed: %v", err))
					os.Exit(util.ExitDecryptFailed)
					return nil
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

			// Verify key fingerprint matches manifest.
			_, keyDigest := crypto.KeyFingerprint(key)
			if keyDigest != br.Manifest.Encryption.KeyID.DigestB64 {
				if usePassword {
					printer.Error(util.ErrDecryptFailed, "wrong password (key fingerprint mismatch)")
				} else {
					printer.Error(util.ErrKeyMismatch, "key fingerprint does not match manifest")
				}
				os.Exit(util.ExitDecryptFailed)
				return nil
			}

			// Decode AAD if present in manifest, or use CLI flag.
			var aad []byte
			if aadStr != "" {
				aad = []byte(aadStr)
			} else if br.Manifest.Encryption.AADB64 != nil {
				aad, err = util.B64Decode(*br.Manifest.Encryption.AADB64)
				if err != nil {
					return fmt.Errorf("decode aad: %w", err)
				}
			}

			var plaintext []byte

			// Auto-detect cipher from manifest.
			cipherName := br.Manifest.Encryption.AEAD

			if br.Manifest.Encryption.IsChunked() {
				// Chunked streaming decryption.
				baseNonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
				if err != nil {
					return fmt.Errorf("decode nonce: %w", err)
				}

				var plaintextBuf bytes.Buffer
				err = crypto.DecryptStream(
					bytes.NewReader(br.Ciphertext),
					&plaintextBuf,
					key, baseNonce, aad,
					*br.Manifest.Encryption.ChunkSize,
					cipherName,
				)
				if err != nil {
					printer.Error(err, "decryption failed")
					os.Exit(util.ExitDecryptFailed)
					return nil
				}
				plaintext = plaintextBuf.Bytes()
			} else {
				// Legacy non-chunked decryption.
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
					printer.Error(err, "decryption failed")
					os.Exit(util.ExitDecryptFailed)
					return nil
				}
			}

			// Decompress if the bundle was compressed.
			if br.Manifest.Compress != nil && br.Manifest.Compress.Algo != "" && br.Manifest.Compress.Algo != "none" {
				plaintext, err = crypto.Decompress(plaintext, br.Manifest.Compress.Algo)
				if err != nil {
					return fmt.Errorf("decompress: %w", err)
				}
			}

			// Write plaintext.
			if azOutURI != "" {
				// Upload directly to Azure.
				if err := azureUploadBytes(plaintext, azOutURI); err != nil {
					return fmt.Errorf("upload to Azure: %w", err)
				}
			} else {
				var output io.Writer
				if useStdout {
					output = os.Stdout
				} else {
					f, err := os.Create(outFile)
					if err != nil {
						return fmt.Errorf("create output: %w", err)
					}
					defer f.Close()
					output = f
				}
				if _, err := output.Write(plaintext); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
			}

			// Output.
			outDesc := outFile
			if azOutURI != "" {
				outDesc = azOutURI
			}
			if useStdout {
				outDesc = "stdout"
			}
			auditOutDesc = outDesc
			auditKeyFP = br.Manifest.Encryption.KeyID.DigestB64
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle": auditInFile,
					"output": outDesc,
					"size":   len(plaintext),
				})
			default:
				printer.Human("Decrypted: %s", auditInFile)
				printer.Human("Output:    %s", outDesc)
				printer.Human("Size:      %d bytes", len(plaintext))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output plaintext path")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to the decryption key")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (overrides manifest AAD)")
	cmd.Flags().BoolVar(&useStdout, "stdout", false, "write decrypted plaintext to standard output")
	cmd.Flags().StringVar(&password, "password", "", "decrypt with a password")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "read password from file")
	cmd.Flags().StringVar(&privKeyFile, "privkey", "", "private key for hybrid decryption (PEM)")
	cmd.Flags().StringVar(&kmsProvider, "kms-provider", "", "KMS provider to unwrap DEK (when bundle has kms_key_id; e.g. aws, mock)")

	return cmd
}
