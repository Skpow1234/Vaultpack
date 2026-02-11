package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newProtectCmd() *cobra.Command {
	var (
		inFile       string
		outFile      string
		keyOutFile   string
		keyFile      string
		aadStr       string
		hashAlgo     string
		cipherName   string
		signFlag     bool
		signingPriv  string
		signAlgo     string
		useStdin     bool
		useStdout    bool
		password     string
		passwordFile string
		kdfAlgo      string
		kdfTime      uint32
		kdfMemory    uint32
		recipients     []string
		compressAlgo   string
		splitShares    int
		splitThreshold int
	)

	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Encrypt a file into a .vpack bundle",
		Long:  "Hash the plaintext, optionally compress, encrypt with an AEAD cipher, and write a portable .vpack bundle.\n\nSupported ciphers: aes-256-gcm (default), chacha20-poly1305, xchacha20-poly1305.\nCompression: --compress gzip|zstd (default: none).\nMultiple recipients: --recipient alice.pem --recipient bob.pem.\nKey splitting: --split-shares 5 --split-threshold 3 (Shamir SSS).\n\nAzure: use az://container/blob paths for --in and/or --out.\n\nUse --stdin to read from standard input and --stdout to write the bundle to standard output.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" && !useStdin {
				return fmt.Errorf("--in or --stdin is required")
			}
			if inFile != "" && useStdin {
				return fmt.Errorf("--in and --stdin are mutually exclusive")
			}
			if signFlag && signingPriv == "" {
				return fmt.Errorf("--signing-priv is required when --sign is set")
			}
			if !crypto.SupportedHashAlgo(hashAlgo) {
				return fmt.Errorf("unsupported hash algorithm %q; supported: sha256, sha512, sha3-256, sha3-512, blake2b-256, blake2b-512, blake3", hashAlgo)
			}
			if !crypto.SupportedCipher(cipherName) {
				return fmt.Errorf("unsupported cipher %q; supported: aes-256-gcm, chacha20-poly1305, xchacha20-poly1305", cipherName)
			}

			// Validate compression algorithm.
			if compressAlgo != crypto.CompressNone && !crypto.SupportedCompression(compressAlgo) {
				return fmt.Errorf("unsupported compression %q; supported: none, gzip, zstd", compressAlgo)
			}

			// Mutual exclusivity: password, key, recipient.
			usePassword := password != "" || passwordFile != ""
			useRecipient := len(recipients) > 0
			keyModes := 0
			if usePassword {
				keyModes++
			}
			if keyFile != "" {
				keyModes++
			}
			if useRecipient {
				keyModes++
			}
			if keyModes > 1 {
				return fmt.Errorf("--password, --key, and --recipient are mutually exclusive")
			}

			// Validate key splitting.
			useSplit := splitShares > 0 || splitThreshold > 0
			if useSplit {
				if splitShares < 2 || splitShares > 255 {
					return fmt.Errorf("--split-shares must be in [2..255]")
				}
				if splitThreshold < 2 || splitThreshold > splitShares {
					return fmt.Errorf("--split-threshold must be in [2..split-shares]")
				}
				if usePassword || useRecipient {
					return fmt.Errorf("--split-shares is only supported with key-file or auto-generated key encryption")
				}
			}

			// Resolve password from file if provided.
			if passwordFile != "" {
				pwData, err := os.ReadFile(passwordFile)
				if err != nil {
					return fmt.Errorf("read password file: %w", err)
				}
				password = strings.TrimRight(string(pwData), "\r\n")
			}

			// Validate KDF algorithm.
			if usePassword && !crypto.SupportedKDF(kdfAlgo) {
				return fmt.Errorf("unsupported KDF %q; supported: argon2id, scrypt, pbkdf2-sha256", kdfAlgo)
			}

			// Azure: download input from blob if az:// URI.
			var azInputCleanup func()
			if isAzure(inFile) {
				tmpPath, err := azureDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from Azure: %w", err)
				}
				azInputCleanup = func() { os.Remove(tmpPath) }
				// Preserve original URI for display, use temp path for local processing.
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
				// We'll write locally to a temp file, then upload.
			}

			// Determine input source.
			var inputReader io.Reader
			var inputName string
			var inputSize int64

			if useStdin {
				inputReader = os.Stdin
				inputName = "stdin"
				inputSize = -1 // unknown
			} else {
				inF, err := os.Open(inFile)
				if err != nil {
					return fmt.Errorf("open input: %w", err)
				}
				defer inF.Close()

				info, err := inF.Stat()
				if err != nil {
					return fmt.Errorf("stat input: %w", err)
				}
				inputReader = inF
				inputName = filepath.Base(inFile)
				inputSize = info.Size()
			}

			// Default output path.
			if outFile == "" && !useStdout {
				if useStdin {
					return fmt.Errorf("--out is required when using --stdin")
				}
				outFile = inFile + ".vpack"
			}

			// If output is Azure, use a temp file as the local write target.
			var azOutCleanup func()
			if azOutURI != "" {
				tmpOut, err := os.CreateTemp("", "vaultpack-az-out-*.vpack")
				if err != nil {
					return fmt.Errorf("create temp output: %w", err)
				}
				tmpOut.Close()
				outFile = tmpOut.Name()
				azOutCleanup = func() { os.Remove(tmpOut.Name()) }
			}
			defer func() {
				if azOutCleanup != nil {
					azOutCleanup()
				}
			}()
			// Default key output path.
			if keyOutFile == "" && keyFile == "" {
				if useStdin {
					keyOutFile = "stdin.key"
				} else {
					keyOutFile = inFile + ".key"
				}
			}

			// When writing to stdout, redirect printer to stderr so only the bundle goes to stdout.
			if useStdout {
				printer.Writer = os.Stderr
			}

			// Stream the plaintext through a TeeReader to hash and buffer simultaneously.
			var plaintextBuf bytes.Buffer
			hashReader := io.TeeReader(inputReader, &plaintextBuf)

			digest, err := crypto.HashReader(hashReader, hashAlgo)
			if err != nil {
				return fmt.Errorf("hash plaintext: %w", err)
			}

			// For stdin, we now know the size.
			if inputSize < 0 {
				inputSize = int64(plaintextBuf.Len())
			}

			// Derive, encapsulate, or load key.
			var key []byte
			var kdfMeta *bundle.KDFMeta
			var hybridMeta *bundle.HybridMeta
			if useRecipient {
				if len(recipients) == 1 {
					// Single-recipient hybrid encryption (backward-compatible).
					recipient := recipients[0]
					scheme, err := crypto.DetectHybridScheme(recipient)
					if err != nil {
						return fmt.Errorf("detect hybrid scheme: %w", err)
					}

					result, err := crypto.HybridEncapsulate(scheme, recipient)
					if err != nil {
						return fmt.Errorf("hybrid encapsulate: %w", err)
					}

					key = result.DEK

					recipientFP, err := crypto.RecipientKeyFingerprint(recipient)
					if err != nil {
						return fmt.Errorf("recipient fingerprint: %w", err)
					}

					hybridMeta = &bundle.HybridMeta{
						Scheme:                  scheme,
						RecipientFingerprintB64: recipientFP,
					}
					if len(result.EphemeralPublicKey) > 0 {
						hybridMeta.EphemeralPubKeyB64 = util.B64Encode(result.EphemeralPublicKey)
					}
					if len(result.WrappedDEK) > 0 {
						hybridMeta.WrappedDEKB64 = util.B64Encode(result.WrappedDEK)
					}
				} else {
					// Multi-recipient: generate one random DEK, wrap for each recipient.
					key, err = crypto.GenerateKey(crypto.AES256KeySize)
					if err != nil {
						return fmt.Errorf("generate DEK: %w", err)
					}

					var recipientEntries []bundle.RecipientEntry
					for _, rp := range recipients {
						scheme, err := crypto.DetectHybridScheme(rp)
						if err != nil {
							return fmt.Errorf("detect hybrid scheme for %s: %w", rp, err)
						}

						result, err := crypto.HybridEncapsulateWithDEK(scheme, rp, key)
						if err != nil {
							return fmt.Errorf("wrap DEK for %s: %w", rp, err)
						}

						fp, err := crypto.RecipientKeyFingerprint(rp)
						if err != nil {
							return fmt.Errorf("recipient fingerprint %s: %w", rp, err)
						}

						entry := bundle.RecipientEntry{
							Scheme:         scheme,
							FingerprintB64: fp,
						}
						if len(result.EphemeralPublicKey) > 0 {
							entry.EphemeralPubKeyB64 = util.B64Encode(result.EphemeralPublicKey)
						}
						if len(result.WrappedDEK) > 0 {
							entry.WrappedDEKB64 = util.B64Encode(result.WrappedDEK)
						}
						recipientEntries = append(recipientEntries, entry)
					}

					hybridMeta = &bundle.HybridMeta{
						Scheme:     "multi-recipient",
						Recipients: recipientEntries,
					}
				}

				// No key file output for hybrid encryption.
				keyOutFile = ""
			} else if usePassword {
				// Password-based key derivation.
				kdfParams, err := crypto.DefaultKDFParams(kdfAlgo)
				if err != nil {
					return fmt.Errorf("kdf params: %w", err)
				}

				// Apply user overrides for Argon2id tuning.
				if kdfAlgo == crypto.KDFArgon2id {
					if cmd.Flags().Changed("kdf-time") {
						kdfParams.Time = kdfTime
					}
					if cmd.Flags().Changed("kdf-memory") {
						kdfParams.Memory = kdfMemory
					}
				}

				// Warn if Argon2id memory is below 32 MB.
				if kdfAlgo == crypto.KDFArgon2id && kdfParams.Memory < 32768 {
					printer.Human("WARNING: Argon2id memory %d KiB is below recommended 32768 KiB (32 MB)", kdfParams.Memory)
				}

				salt, err := crypto.GenerateKDFSalt()
				if err != nil {
					return fmt.Errorf("generate salt: %w", err)
				}

				kdfParams.SaltB64 = util.B64Encode(salt)

				key, err = crypto.DeriveKey([]byte(password), salt, kdfParams, crypto.AES256KeySize)
				if err != nil {
					return fmt.Errorf("derive key: %w", err)
				}

				kdfMeta = &bundle.KDFMeta{
					Algo:       kdfParams.Algo,
					SaltB64:    kdfParams.SaltB64,
					Time:       kdfParams.Time,
					Memory:     kdfParams.Memory,
					Threads:    kdfParams.Threads,
					N:          kdfParams.N,
					R:          kdfParams.R,
					P:          kdfParams.P,
					Iterations: kdfParams.Iterations,
				}

				// No key file output for password-based encryption.
				keyOutFile = ""
			} else if keyFile != "" {
				key, err = crypto.LoadKeyFile(keyFile)
				if err != nil {
					return fmt.Errorf("load key: %w", err)
				}
			} else {
				key, err = crypto.GenerateKey(crypto.AES256KeySize)
				if err != nil {
					return fmt.Errorf("generate key: %w", err)
				}
			}

			// Parse optional AAD.
			var aad []byte
			if aadStr != "" {
				aad = []byte(aadStr)
			}

			// Optional pre-encryption compression.
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

			// Encrypt using chunked streaming.
			var ciphertextBuf bytes.Buffer
			streamResult, err := crypto.EncryptStream(
				&plaintextBuf, &ciphertextBuf, key, aad, crypto.DefaultChunkSize, cipherName,
			)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}

			// Build manifest.
			keyAlgo, keyDigest := crypto.KeyFingerprint(key)

			var aadB64 *string
			if aad != nil {
				s := util.B64Encode(aad)
				aadB64 = &s
			}

			chunkSize := crypto.DefaultChunkSize

			// Build key splitting metadata (if requested).
			var splitMeta *bundle.KeySplitMeta
			if useSplit {
				splitMeta = &bundle.KeySplitMeta{
					Scheme:    "shamir-gf256",
					Threshold: splitThreshold,
					Total:     splitShares,
				}
			}

			// Select manifest version: v2 if using new features, v1 for backward compat.
			manifestVer := bundle.ManifestVersionV1
			if compMeta != nil || (hybridMeta != nil && len(hybridMeta.Recipients) > 0) || splitMeta != nil {
				manifestVer = bundle.ManifestVersionV2
			}

			m := &bundle.Manifest{
				Version:   manifestVer,
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
				Input: bundle.InputMeta{
					Name: inputName,
					Size: inputSize,
				},
				Plaintext: bundle.PlaintextHash{
					Algo:      hashAlgo,
					DigestB64: util.B64Encode(digest),
				},
				Encryption: bundle.EncryptionMeta{
					AEAD:      cipherName,
					NonceB64:  util.B64Encode(streamResult.BaseNonce),
					TagB64:    util.B64Encode(streamResult.LastTag),
					AADB64:    aadB64,
					ChunkSize: &chunkSize,
					KDF:       kdfMeta,
					Hybrid:    hybridMeta,
					KeyID: bundle.KeyID{
						Algo:      keyAlgo,
						DigestB64: keyDigest,
					},
				},
				Ciphertext: bundle.CiphertextMeta{
					Size: streamResult.CiphertextSize,
				},
				Compress:     compMeta,
				KeySplitting: splitMeta,
			}

			manifestBytes, err := bundle.MarshalManifest(m)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}

			// Optionally sign.
			var sig []byte
			var resolvedSignAlgo string
			if signFlag {
				privKey, detectedAlgo, err := crypto.LoadPrivateKey(signingPriv)
				if err != nil {
					return fmt.Errorf("load signing key: %w", err)
				}

				resolvedSignAlgo = detectedAlgo
				if signAlgo != "" && signAlgo != detectedAlgo {
					return fmt.Errorf("--sign-algo %q does not match key type %q", signAlgo, detectedAlgo)
				}

				// Store signing algo and timestamp in manifest.
				m.SignatureAlgo = &resolvedSignAlgo
				signTS := time.Now().UTC().Format(time.RFC3339)
				m.SignedAt = &signTS

				canonical, err := bundle.CanonicalManifest(m)
				if err != nil {
					return fmt.Errorf("canonicalize manifest: %w", err)
				}

				payloadHash, err := crypto.HashReader(
					bytes.NewReader(ciphertextBuf.Bytes()), "sha256",
				)
				if err != nil {
					return fmt.Errorf("hash payload: %w", err)
				}

				sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
				sig, err = crypto.SignMessage(privKey, resolvedSignAlgo, sigMsg)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}

				// Re-marshal manifest (it now includes signature_algo).
				manifestBytes, err = bundle.MarshalManifest(m)
				if err != nil {
					return fmt.Errorf("re-marshal manifest: %w", err)
				}
			}

			// Write bundle.
			if useStdout {
				err = bundle.Write(&bundle.WriteParams{
					OutputPath:    "", // unused for stdout
					Payload:       &ciphertextBuf,
					ManifestBytes: manifestBytes,
					Signature:     sig,
					Writer:        os.Stdout,
				})
			} else {
				err = bundle.Write(&bundle.WriteParams{
					OutputPath:    outFile,
					Payload:       &ciphertextBuf,
					ManifestBytes: manifestBytes,
					Signature:     sig,
				})
			}
			if err != nil {
				return fmt.Errorf("write bundle: %w", err)
			}

			// Upload to Azure if the output URI was az://.
			if azOutURI != "" {
				if err := azureUploadFile(outFile, azOutURI); err != nil {
					return fmt.Errorf("upload bundle to Azure: %w", err)
				}
			}

			// Save key file if we generated one.
			if keyOutFile != "" && !useSplit {
				if err := crypto.SaveKeyFile(keyOutFile, key); err != nil {
					return fmt.Errorf("save key: %w", err)
				}
			}

			// Split key into Shamir shares if requested.
			var sharePaths []string
			if useSplit {
				// Read the raw key file bytes that would normally be written.
				keyFileData := []byte(crypto.KeyFilePrefix + util.B64Encode(key) + "\n")

				splitResult, err := crypto.SplitSecret(keyFileData, splitShares, splitThreshold)
				if err != nil {
					return fmt.Errorf("split key: %w", err)
				}

				shareDir := filepath.Dir(keyOutFile)
				shareBase := filepath.Base(keyOutFile)
				sharePaths = make([]string, len(splitResult))
				for _, s := range splitResult {
					name := fmt.Sprintf("%s.share%d", shareBase, s.Index)
					p := filepath.Join(shareDir, name)
					data := crypto.MarshalShare(s)
					if err := os.WriteFile(p, data, 0o600); err != nil {
						return fmt.Errorf("write share %d: %w", s.Index, err)
					}
					sharePaths[int(s.Index)-1] = p
				}
			}

			// Output.
			signed := signFlag
			_ = resolvedSignAlgo // used below
			outDesc := outFile
			if azOutURI != "" {
				outDesc = azOutURI
			}
			if useStdout {
				outDesc = "stdout"
			}
			switch printer.Mode {
			case OutputJSON:
				result := map[string]any{
					"bundle":      outDesc,
					"key_file":    keyOutFile,
					"input":       inputName,
					"input_size":  inputSize,
					"cipher":      cipherName,
					"hash_algo":   hashAlgo,
					"hash_digest": util.B64Encode(digest),
					"signed":      signed,
					"chunked":     true,
					"chunk_size":  chunkSize,
					"version":     manifestVer,
				}
				if usePassword {
					result["kdf"] = kdfAlgo
					result["password_protected"] = true
				}
				if useRecipient {
					result["hybrid_scheme"] = hybridMeta.Scheme
					result["recipient_encrypted"] = true
					result["recipient_count"] = len(recipients)
				}
				if compMeta != nil {
					result["compression"] = compressAlgo
					result["original_size"] = compMeta.OriginalSize
				}
				if useSplit {
					result["key_split"] = map[string]any{
						"scheme":    "shamir-gf256",
						"threshold": splitThreshold,
						"total":     splitShares,
						"shares":    sharePaths,
					}
				}
				return printer.JSON(result)
			default:
				printer.Human("Protected: %s", inputName)
				printer.Human("Bundle:    %s", outDesc)
				if keyOutFile != "" && !useSplit {
					printer.Human("Key:       %s", keyOutFile)
				}
				if useSplit {
					printer.Human("Key split: %d-of-%d Shamir shares", splitThreshold, splitShares)
					for _, sp := range sharePaths {
						printer.Human("  Share:   %s", sp)
					}
				}
				if useRecipient {
					printer.Human("Hybrid:    %s (%d recipient(s))", hybridMeta.Scheme, len(recipients))
				}
				if usePassword {
					printer.Human("KDF:       %s", kdfAlgo)
				}
				printer.Human("Cipher:    %s (chunked, %d byte chunks)", cipherName, chunkSize)
				if compMeta != nil {
					printer.Human("Compress:  %s (%d → %d bytes)", compressAlgo, compMeta.OriginalSize, plaintextBuf.Len())
				}
				printer.Human("Hash:      %s:%s", hashAlgo, util.B64Encode(digest))
				if signed {
					printer.Human("Signed:    yes (%s)", resolvedSignAlgo)
				}
				printer.Human("Version:   %s", manifestVer)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input file to protect")
	cmd.Flags().StringVar(&outFile, "out", "", "output .vpack path (default: <input>.vpack)")
	cmd.Flags().StringVar(&keyOutFile, "key-out", "", "path to write the generated key (default: <input>.key)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to an existing key (skips key generation)")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (e.g. 'env=prod,app=payments')")
	cmd.Flags().StringVar(&hashAlgo, "hash-algo", "sha256", "hash algorithm for plaintext: sha256, sha512, sha3-256, sha3-512, blake2b-256, blake2b-512, blake3")
	cmd.Flags().StringVar(&cipherName, "cipher", crypto.CipherAES256GCM, "AEAD cipher: aes-256-gcm, chacha20-poly1305, xchacha20-poly1305")
	cmd.Flags().BoolVar(&signFlag, "sign", false, "sign the bundle")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to private signing key (required with --sign)")
	cmd.Flags().StringVar(&signAlgo, "sign-algo", "", "signing algorithm (auto-detected from key if omitted)")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "read plaintext from standard input")
	cmd.Flags().BoolVar(&useStdout, "stdout", false, "write bundle to standard output")
	cmd.Flags().StringVar(&password, "password", "", "encrypt with a password (instead of a key file)")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "read password from file")
	cmd.Flags().StringVar(&kdfAlgo, "kdf", crypto.KDFArgon2id, "key derivation function: argon2id, scrypt, pbkdf2-sha256")
	cmd.Flags().Uint32Var(&kdfTime, "kdf-time", 0, "Argon2id time parameter (default: 3)")
	cmd.Flags().Uint32Var(&kdfMemory, "kdf-memory", 0, "Argon2id memory parameter in KiB (default: 65536 = 64MB)")
	cmd.Flags().StringArrayVar(&recipients, "recipient", nil, "recipient's PEM public key (hybrid encryption, repeatable for multi-recipient)")
	cmd.Flags().StringVar(&compressAlgo, "compress", crypto.CompressNone, "pre-encryption compression: none, gzip, zstd")
	cmd.Flags().IntVar(&splitShares, "split-shares", 0, "split the key into N Shamir shares (requires --split-threshold)")
	cmd.Flags().IntVar(&splitThreshold, "split-threshold", 0, "minimum shares to reconstruct (K-of-N, requires --split-shares)")

	return cmd
}
