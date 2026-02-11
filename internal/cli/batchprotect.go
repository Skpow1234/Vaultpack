package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newBatchProtectCmd() *cobra.Command {
	var (
		srcDir       string
		outDir       string
		keyOutFile   string
		perFileKey   bool
		cipherName   string
		hashAlgo     string
		compressAlgo string
		workers      int
		include      []string
		exclude      []string
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:   "batch-protect",
		Short: "Encrypt all files in a directory into .vpack bundles",
		Long: `Recursively encrypt every file in a directory, preserving the directory structure.

By default a single shared key is generated for the entire batch.
Use --per-file-key to generate a unique key for each file.

Azure: use az://container/prefix/ paths for --dir and/or --out-dir.

Example:
  vaultpack batch-protect --dir ./exports/ --out-dir ./encrypted/ --key-out batch.key
  vaultpack batch-protect --dir ./data/ --out-dir ./enc/ --per-file-key --workers 8
  vaultpack batch-protect --dir ./logs/ --out-dir ./enc/ --include "*.csv" --exclude "*.tmp" --dry-run
  vaultpack batch-protect --dir az://mycontainer/data/ --out-dir az://mycontainer/encrypted/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if srcDir == "" {
				return fmt.Errorf("--dir is required")
			}
			if outDir == "" {
				return fmt.Errorf("--out-dir is required")
			}
			if !crypto.SupportedCipher(cipherName) {
				return fmt.Errorf("unsupported cipher %q", cipherName)
			}
			if !crypto.SupportedHashAlgo(hashAlgo) {
				return fmt.Errorf("unsupported hash algorithm %q", hashAlgo)
			}
			if compressAlgo != crypto.CompressNone && !crypto.SupportedCompression(compressAlgo) {
				return fmt.Errorf("unsupported compression %q", compressAlgo)
			}

			// Azure source: download blobs to temp dir.
			azSrcURI := ""
			var azSrcCleanup func()
			if isAzure(srcDir) {
				azSrcURI = srcDir
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
			localOutDir := outDir
			if isAzure(outDir) {
				azOutURI = outDir
				tmpOut, err := os.MkdirTemp("", "vaultpack-az-batch-out-*")
				if err != nil {
					return fmt.Errorf("create temp output dir: %w", err)
				}
				defer os.RemoveAll(tmpOut)
				localOutDir = tmpOut
				outDir = localOutDir
			}
			_ = azSrcURI

			// Collect files.
			files, err := collectFiles(srcDir, include, exclude)
			if err != nil {
				return fmt.Errorf("scan directory: %w", err)
			}
			if len(files) == 0 {
				printer.Human("No files found in %s", srcDir)
				return nil
			}

			entries := buildBatchEntries(files, srcDir, outDir, ".vpack")

			// Dry-run: just list.
			if dryRun {
				if printer.Mode == OutputJSON {
					items := make([]map[string]string, len(entries))
					for i, e := range entries {
						items[i] = map[string]string{
							"input":  e.RelPath,
							"output": e.OutputPath,
						}
					}
					return printer.JSON(map[string]any{
						"dry_run": true,
						"total":   len(entries),
						"files":   items,
					})
				}
				printer.Human("Dry run: %d file(s) would be processed", len(entries))
				for _, e := range entries {
					printer.Human("  %s → %s", e.RelPath, e.OutputPath)
				}
				return nil
			}

			// Create output directory.
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			// Generate a shared batch key (unless per-file).
			var sharedKey []byte
			if !perFileKey {
				sharedKey, err = crypto.GenerateKey(crypto.AES256KeySize)
				if err != nil {
					return fmt.Errorf("generate batch key: %w", err)
				}
				keyPath := keyOutFile
				if keyPath == "" {
					keyPath = filepath.Join(outDir, "batch.key")
				}
				if err := crypto.SaveKeyFile(keyPath, sharedKey); err != nil {
					return fmt.Errorf("save batch key: %w", err)
				}
				keyOutFile = keyPath
			}

			// Process function: encrypts one file.
			protectOne := func(entry BatchFileEntry) error {
				// Ensure output parent directory exists.
				if err := ensureParentDir(entry.OutputPath); err != nil {
					return fmt.Errorf("create output dir: %w", err)
				}

				// Open input file.
				inF, err := os.Open(entry.InputPath)
				if err != nil {
					return fmt.Errorf("open input: %w", err)
				}
				defer inF.Close()

				info, err := inF.Stat()
				if err != nil {
					return fmt.Errorf("stat input: %w", err)
				}

				// Hash + buffer plaintext.
				var plaintextBuf bytes.Buffer
				hashReader := io.TeeReader(inF, &plaintextBuf)
				digest, err := crypto.HashReader(hashReader, hashAlgo)
				if err != nil {
					return fmt.Errorf("hash: %w", err)
				}

				// Select key.
				var key []byte
				if perFileKey {
					key, err = crypto.GenerateKey(crypto.AES256KeySize)
					if err != nil {
						return fmt.Errorf("generate key: %w", err)
					}
					// Save per-file key alongside the bundle.
					keyPath := entry.OutputPath + ".key"
					if err := crypto.SaveKeyFile(keyPath, key); err != nil {
						return fmt.Errorf("save key: %w", err)
					}
				} else {
					key = sharedKey
				}

				// Optional compression.
				var compMeta *bundle.CompressionMeta
				if compressAlgo != crypto.CompressNone {
					originalSize := int64(plaintextBuf.Len())
					compressed, err := crypto.Compress(plaintextBuf.Bytes(), compressAlgo)
					if err != nil {
						return fmt.Errorf("compress: %w", err)
					}
					compMeta = &bundle.CompressionMeta{
						Algo:         compressAlgo,
						OriginalSize: originalSize,
					}
					plaintextBuf.Reset()
					plaintextBuf.Write(compressed)
				}

				// Encrypt.
				var ciphertextBuf bytes.Buffer
				streamResult, err := crypto.EncryptStream(
					&plaintextBuf, &ciphertextBuf, key, nil, crypto.DefaultChunkSize, cipherName,
				)
				if err != nil {
					return fmt.Errorf("encrypt: %w", err)
				}

				// Build manifest.
				keyAlgo, keyDigest := crypto.KeyFingerprint(key)
				chunkSize := crypto.DefaultChunkSize

				manifestVer := bundle.ManifestVersionV1
				if compMeta != nil {
					manifestVer = bundle.ManifestVersionV2
				}

				m := &bundle.Manifest{
					Version:   manifestVer,
					CreatedAt: time.Now().UTC().Format(time.RFC3339),
					Input: bundle.InputMeta{
						Name: filepath.Base(entry.InputPath),
						Size: info.Size(),
					},
					Plaintext: bundle.PlaintextHash{
						Algo:      hashAlgo,
						DigestB64: util.B64Encode(digest),
					},
					Encryption: bundle.EncryptionMeta{
						AEAD:      cipherName,
						NonceB64:  util.B64Encode(streamResult.BaseNonce),
						TagB64:    util.B64Encode(streamResult.LastTag),
						ChunkSize: &chunkSize,
						KeyID: bundle.KeyID{
							Algo:      keyAlgo,
							DigestB64: keyDigest,
						},
					},
					Ciphertext: bundle.CiphertextMeta{
						Size: streamResult.CiphertextSize,
					},
					Compress: compMeta,
				}

				manifestBytes, err := bundle.MarshalManifest(m)
				if err != nil {
					return fmt.Errorf("marshal manifest: %w", err)
				}

				// Write bundle.
				err = bundle.Write(&bundle.WriteParams{
					OutputPath:    entry.OutputPath,
					Payload:       &ciphertextBuf,
					ManifestBytes: manifestBytes,
				})
				if err != nil {
					return fmt.Errorf("write bundle: %w", err)
				}

				return nil
			}

			// Run in parallel.
			printer.Human("Batch protect: %d file(s) with %d worker(s)", len(entries), workers)
			results := runParallel(entries, workers, protectOne, printer)

			// Tally results.
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
				Operation: "protect",
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
				if keyOutFile != "" && !perFileKey {
					printer.Human("Batch key: %s", keyOutFile)
				}
				if perFileKey {
					printer.Human("Per-file keys: alongside each .vpack bundle")
				}
				for _, r := range results {
					if r.Status == "error" {
						printer.Human("  FAIL: %s — %s", r.RelPath, r.Error)
					}
				}
				printer.Human("Batch manifest: %s", displayOutDir+"/batch-manifest.json")
			}

			if failed > 0 {
				return fmt.Errorf("%d of %d files failed", failed, len(entries))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&srcDir, "dir", "", "source directory to encrypt (required)")
	f.StringVar(&outDir, "out-dir", "", "output directory for .vpack bundles (required)")
	f.StringVar(&keyOutFile, "key-out", "", "path for the batch key file (default: <out-dir>/batch.key)")
	f.BoolVar(&perFileKey, "per-file-key", false, "generate a unique key per file instead of a shared batch key")
	f.StringVar(&cipherName, "cipher", crypto.CipherAES256GCM, "AEAD cipher")
	f.StringVar(&hashAlgo, "hash-algo", "sha256", "hash algorithm")
	f.StringVar(&compressAlgo, "compress", crypto.CompressNone, "pre-encryption compression: none, gzip, zstd")
	f.IntVar(&workers, "workers", 0, "number of parallel workers (default: NumCPU)")
	f.StringArrayVar(&include, "include", nil, "glob pattern for files to include (e.g. '*.csv')")
	f.StringArrayVar(&exclude, "exclude", nil, "glob pattern for files to exclude (e.g. '*.log')")
	f.BoolVar(&dryRun, "dry-run", false, "preview which files would be processed without encrypting")

	return cmd
}
