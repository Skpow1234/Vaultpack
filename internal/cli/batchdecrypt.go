package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newBatchDecryptCmd() *cobra.Command {
	var (
		srcDir       string
		outDir       string
		keyFile      string
		password     string
		passwordFile string
		workers      int
	)

	cmd := &cobra.Command{
		Use:   "batch-decrypt",
		Short: "Decrypt all .vpack bundles in a directory",
		Long: `Recursively find and decrypt all .vpack bundles in a directory, preserving
the directory structure. The .vpack extension is stripped from the output filenames.

Use a shared key (--key), per-file keys (auto-detected alongside bundles), or a password.

Azure: use az://container/prefix/ paths for --dir and/or --out-dir.

Example:
  vaultpack batch-decrypt --dir ./encrypted/ --out-dir ./decrypted/ --key batch.key
  vaultpack batch-decrypt --dir ./encrypted/ --out-dir ./decrypted/ --password "passphrase"
  vaultpack batch-decrypt --dir az://mycontainer/encrypted/ --out-dir az://mycontainer/decrypted/ --key batch.key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if srcDir == "" {
				return fmt.Errorf("--dir is required")
			}
			if outDir == "" {
				return fmt.Errorf("--out-dir is required")
			}

			// Azure source: download blobs to temp dir.
			var azSrcCleanup func()
			if isAzure(srcDir) {
				localDir, cleanup, err := azureDownloadDir(srcDir)
				if err != nil {
					return fmt.Errorf("download from Azure: %w", err)
				}
				azSrcCleanup = cleanup
				srcDir = localDir
			}
			defer func() {
				if azSrcCleanup != nil {
					azSrcCleanup()
				}
			}()

			// Azure output: write to temp dir, upload after.
			azOutURI := ""
			if isAzure(outDir) {
				azOutURI = outDir
				tmpOut, err := os.MkdirTemp("", "vaultpack-az-bdec-out-*")
				if err != nil {
					return fmt.Errorf("create temp output dir: %w", err)
				}
				defer os.RemoveAll(tmpOut)
				outDir = tmpOut
			}

			// Resolve password from file.
			if passwordFile != "" {
				pwData, err := os.ReadFile(passwordFile)
				if err != nil {
					return fmt.Errorf("read password file: %w", err)
				}
				password = strings.TrimRight(string(pwData), "\r\n")
			}

			usePassword := password != ""

			// Collect .vpack files.
			files, err := collectVpackFiles(srcDir)
			if err != nil {
				return fmt.Errorf("scan directory: %w", err)
			}
			if len(files) == 0 {
				printer.Human("No .vpack files found in %s", srcDir)
				return nil
			}

			entries := buildBatchDecryptEntries(files, srcDir, outDir)

			// Create output directory.
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			// Load shared key (if provided).
			var sharedKey []byte
			if keyFile != "" {
				sharedKey, err = crypto.LoadKeyFile(keyFile)
				if err != nil {
					return fmt.Errorf("load key: %w", err)
				}
			}

			// Process function: decrypts one bundle.
			decryptOne := func(entry BatchFileEntry) error {
				if err := ensureParentDir(entry.OutputPath); err != nil {
					return fmt.Errorf("create output dir: %w", err)
				}

				br, err := bundle.Read(entry.InputPath)
				if err != nil {
					return fmt.Errorf("read bundle: %w", err)
				}

				// Determine key.
				var key []byte
				if usePassword {
					// Password-based decryption.
					if br.Manifest.Encryption.KDF == nil {
						return fmt.Errorf("bundle is not password-protected")
					}
					kdfM := br.Manifest.Encryption.KDF
					salt, err := util.B64Decode(kdfM.SaltB64)
					if err != nil {
						return fmt.Errorf("decode salt: %w", err)
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
				} else if sharedKey != nil {
					key = sharedKey
				} else {
					// Try per-file key: look for <bundle>.key alongside the bundle.
					perFileKeyPath := entry.InputPath + ".key"
					if _, err := os.Stat(perFileKeyPath); err == nil {
						key, err = crypto.LoadKeyFile(perFileKeyPath)
						if err != nil {
							return fmt.Errorf("load per-file key: %w", err)
						}
					} else {
						return fmt.Errorf("no key provided and no per-file key found at %s", perFileKeyPath)
					}
				}

				// Verify key fingerprint.
				_, keyDigest := crypto.KeyFingerprint(key)
				if keyDigest != br.Manifest.Encryption.KeyID.DigestB64 {
					return fmt.Errorf("key fingerprint mismatch")
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
				var plaintext []byte
				cipherName := br.Manifest.Encryption.AEAD

				if br.Manifest.Encryption.IsChunked() {
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
						return fmt.Errorf("decrypt: %w", err)
					}
					plaintext = plaintextBuf.Bytes()
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
						return fmt.Errorf("decrypt: %w", err)
					}
				}

				// Decompress if needed.
				if br.Manifest.Compress != nil && br.Manifest.Compress.Algo != "" && br.Manifest.Compress.Algo != "none" {
					plaintext, err = crypto.Decompress(plaintext, br.Manifest.Compress.Algo)
					if err != nil {
						return fmt.Errorf("decompress: %w", err)
					}
				}

				// Write output.
				if err := os.WriteFile(entry.OutputPath, plaintext, 0o600); err != nil {
					return fmt.Errorf("write output: %w", err)
				}

				return nil
			}

			// Run in parallel.
			printer.Human("Batch decrypt: %d bundle(s) with %d worker(s)", len(entries), workers)
			results := runParallel(entries, workers, decryptOne, printer)

			// Tally.
			succeeded := 0
			failed := 0
			for _, r := range results {
				if r.Status == "ok" {
					succeeded++
				} else {
					failed++
				}
			}

			// Write batch-manifest.json.
			bm := &BatchManifest{
				Operation: "decrypt",
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
				SourceDir: srcDir,
				OutputDir: outDir,
				Workers:   workers,
				Total:     len(entries),
				Succeeded: succeeded,
				Failed:    failed,
				Results:   results,
			}
			if err := writeBatchManifest(outDir, bm); err != nil {
				printer.Error(err, "failed to write batch manifest")
			}

			// Upload results to Azure if output was az://.
			if azOutURI != "" {
				if err := azureUploadDir(outDir, azOutURI); err != nil {
					return fmt.Errorf("upload batch results to Azure: %w", err)
				}
			}

			// Display output directory.
			displayOutDir := outDir
			if azOutURI != "" {
				displayOutDir = azOutURI
			}

			// Output.
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(bm)
			default:
				printer.Human("")
				printer.Human("Results: %d succeeded, %d failed, %d total", succeeded, failed, len(entries))
				for _, r := range results {
					if r.Status == "error" {
						printer.Human("  FAIL: %s — %s", r.RelPath, r.Error)
					}
				}
				printer.Human("Batch manifest: %s", displayOutDir+"/batch-manifest.json")
			}

			if failed > 0 {
				return fmt.Errorf("%d of %d bundles failed", failed, len(entries))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&srcDir, "dir", "", "source directory with .vpack bundles (required)")
	f.StringVar(&outDir, "out-dir", "", "output directory for decrypted files (required)")
	f.StringVar(&keyFile, "key", "", "path to shared batch decryption key")
	f.StringVar(&password, "password", "", "decrypt with a password")
	f.StringVar(&passwordFile, "password-file", "", "read password from file")
	f.IntVar(&workers, "workers", 0, "number of parallel workers (default: NumCPU)")

	return cmd
}
