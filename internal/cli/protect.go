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

func newProtectCmd() *cobra.Command {
	var (
		inFile      string
		outFile     string
		keyOutFile  string
		keyFile     string
		aadStr      string
		signFlag    bool
		signingPriv string
		useStdin    bool
		useStdout   bool
	)

	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Encrypt a file into a .vpack bundle",
		Long:  "Hash the plaintext, encrypt with AES-256-GCM, and write a portable .vpack bundle. Optionally sign with Ed25519.\n\nUse --stdin to read from standard input and --stdout to write the bundle to standard output.",
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

			digest, err := crypto.HashReader(hashReader, "sha256")
			if err != nil {
				return fmt.Errorf("hash plaintext: %w", err)
			}

			// For stdin, we now know the size.
			if inputSize < 0 {
				inputSize = int64(plaintextBuf.Len())
			}

			// Load or generate key.
			var key []byte
			if keyFile != "" {
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

			// Encrypt using chunked streaming.
			var ciphertextBuf bytes.Buffer
			streamResult, err := crypto.EncryptStream(
				&plaintextBuf, &ciphertextBuf, key, aad, crypto.DefaultChunkSize,
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

			m := &bundle.Manifest{
				Version:   bundle.ManifestVersion,
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
				Input: bundle.InputMeta{
					Name: inputName,
					Size: inputSize,
				},
				Plaintext: bundle.PlaintextHash{
					Algo:      "sha256",
					DigestB64: util.B64Encode(digest),
				},
				Encryption: bundle.EncryptionMeta{
					AEAD:      "aes-256-gcm",
					NonceB64:  util.B64Encode(streamResult.BaseNonce),
					TagB64:    util.B64Encode(streamResult.LastTag),
					AADB64:    aadB64,
					ChunkSize: &chunkSize,
					KeyID: bundle.KeyID{
						Algo:      keyAlgo,
						DigestB64: keyDigest,
					},
				},
				Ciphertext: bundle.CiphertextMeta{
					Size: streamResult.CiphertextSize,
				},
			}

			manifestBytes, err := bundle.MarshalManifest(m)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}

			// Optionally sign.
			var sig []byte
			if signFlag {
				privKey, err := crypto.LoadSigningKey(signingPriv)
				if err != nil {
					return fmt.Errorf("load signing key: %w", err)
				}

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
				sig = crypto.Sign(privKey, sigMsg)
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

			// Save key file if we generated one.
			if keyOutFile != "" {
				if err := crypto.SaveKeyFile(keyOutFile, key); err != nil {
					return fmt.Errorf("save key: %w", err)
				}
			}

			// Output.
			signed := signFlag
			outDesc := outFile
			if useStdout {
				outDesc = "stdout"
			}
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":      outDesc,
					"key_file":    keyOutFile,
					"input":       inputName,
					"input_size":  inputSize,
					"algo":        "aes-256-gcm",
					"hash_algo":   "sha256",
					"hash_digest": util.B64Encode(digest),
					"signed":      signed,
					"chunked":     true,
					"chunk_size":  chunkSize,
				})
			default:
				printer.Human("Protected: %s", inputName)
				printer.Human("Bundle:    %s", outDesc)
				if keyOutFile != "" {
					printer.Human("Key:       %s", keyOutFile)
				}
				printer.Human("Algo:      aes-256-gcm (chunked, %d byte chunks)", chunkSize)
				printer.Human("Hash:      sha256:%s", util.B64Encode(digest))
				if signed {
					printer.Human("Signed:    yes (ed25519)")
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input file to protect")
	cmd.Flags().StringVar(&outFile, "out", "", "output .vpack path (default: <input>.vpack)")
	cmd.Flags().StringVar(&keyOutFile, "key-out", "", "path to write the generated key (default: <input>.key)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to an existing key (skips key generation)")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (e.g. 'env=prod,app=payments')")
	cmd.Flags().BoolVar(&signFlag, "sign", false, "sign the bundle with Ed25519")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to Ed25519 private key (required with --sign)")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "read plaintext from standard input")
	cmd.Flags().BoolVar(&useStdout, "stdout", false, "write bundle to standard output")

	return cmd
}
