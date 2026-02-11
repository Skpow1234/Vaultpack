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
	)

	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Encrypt a file into a .vpack bundle",
		Long:  "Hash the plaintext, encrypt with AES-256-GCM, and write a portable .vpack bundle. Optionally sign with Ed25519.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if signFlag && signingPriv == "" {
				return fmt.Errorf("--signing-priv is required when --sign is set")
			}

			// Default output path: input + .vpack extension.
			if outFile == "" {
				outFile = inFile + ".vpack"
			}
			// Default key output path: input + .key extension.
			if keyOutFile == "" && keyFile == "" {
				keyOutFile = inFile + ".key"
			}

			// Open input file for streaming.
			inF, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("open input: %w", err)
			}
			defer inF.Close()

			info, err := inF.Stat()
			if err != nil {
				return fmt.Errorf("stat input: %w", err)
			}
			inputSize := info.Size()

			// Stream the plaintext through a TeeReader to hash and buffer simultaneously.
			// The buffer holds the plaintext for encryption.
			var plaintextBuf bytes.Buffer
			hashReader := io.TeeReader(inF, &plaintextBuf)

			digest, err := crypto.HashReader(hashReader, "sha256")
			if err != nil {
				return fmt.Errorf("hash plaintext: %w", err)
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
					Name: filepath.Base(inFile),
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

			// Write bundle with streaming payload.
			err = bundle.Write(&bundle.WriteParams{
				OutputPath:    outFile,
				Payload:       &ciphertextBuf,
				ManifestBytes: manifestBytes,
				Signature:     sig,
			})
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
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":      outFile,
					"key_file":    keyOutFile,
					"input":       inFile,
					"input_size":  inputSize,
					"algo":        "aes-256-gcm",
					"hash_algo":   "sha256",
					"hash_digest": util.B64Encode(digest),
					"signed":      signed,
					"chunked":     true,
					"chunk_size":  chunkSize,
				})
			default:
				printer.Human("Protected: %s", inFile)
				printer.Human("Bundle:    %s", outFile)
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

	cmd.Flags().StringVar(&inFile, "in", "", "input file to protect (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output .vpack path (default: <input>.vpack)")
	cmd.Flags().StringVar(&keyOutFile, "key-out", "", "path to write the generated key (default: <input>.key)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to an existing key (skips key generation)")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (e.g. 'env=prod,app=payments')")
	cmd.Flags().BoolVar(&signFlag, "sign", false, "sign the bundle with Ed25519")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to Ed25519 private key (required with --sign)")

	return cmd
}
