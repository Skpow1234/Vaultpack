package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	var (
		inFile    string
		outFile   string
		keyFile   string
		aadStr    string
		useStdout bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a .vpack bundle",
		Long:  "Read a .vpack bundle, decrypt the payload using the provided key, and write the plaintext.\n\nUse --stdout to write decrypted plaintext to standard output.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if keyFile == "" {
				return fmt.Errorf("--key is required")
			}
			if outFile == "" && !useStdout {
				return fmt.Errorf("--out or --stdout is required")
			}

			// When writing to stdout, redirect printer to stderr.
			if useStdout {
				printer.Writer = os.Stderr
			}

			// Read bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			// Load key.
			key, err := crypto.LoadKeyFile(keyFile)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}

			// Verify key fingerprint matches manifest.
			_, keyDigest := crypto.KeyFingerprint(key)
			if keyDigest != br.Manifest.Encryption.KeyID.DigestB64 {
				printer.Error(util.ErrKeyMismatch, "key fingerprint does not match manifest")
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

				plaintext, err = crypto.DecryptAESGCM(br.Ciphertext, key, nonce, tag, aad)
				if err != nil {
					printer.Error(err, "decryption failed")
					os.Exit(util.ExitDecryptFailed)
					return nil
				}
			}

			// Write plaintext.
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

			// Output.
			outDesc := outFile
			if useStdout {
				outDesc = "stdout"
			}
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle": inFile,
					"output": outDesc,
					"size":   len(plaintext),
				})
			default:
				printer.Human("Decrypted: %s", inFile)
				printer.Human("Output:    %s", outDesc)
				printer.Human("Size:      %d bytes", len(plaintext))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output plaintext path")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to the decryption key (required)")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (overrides manifest AAD)")
	cmd.Flags().BoolVar(&useStdout, "stdout", false, "write decrypted plaintext to standard output")

	return cmd
}
