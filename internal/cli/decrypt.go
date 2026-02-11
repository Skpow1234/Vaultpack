package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	var (
		inFile  string
		outFile string
		keyFile string
		aadStr  string
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a .vpack bundle",
		Long:  "Read a .vpack bundle, decrypt the payload using the provided key, and write the plaintext.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if keyFile == "" {
				return fmt.Errorf("--key is required")
			}
			if outFile == "" {
				return fmt.Errorf("--out is required")
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

			// Decode nonce and tag from manifest.
			nonce, err := util.B64Decode(br.Manifest.Encryption.NonceB64)
			if err != nil {
				return fmt.Errorf("decode nonce: %w", err)
			}
			tag, err := util.B64Decode(br.Manifest.Encryption.TagB64)
			if err != nil {
				return fmt.Errorf("decode tag: %w", err)
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

			// Decrypt.
			plaintext, err := crypto.DecryptAESGCM(br.Ciphertext, key, nonce, tag, aad)
			if err != nil {
				printer.Error(err, "decryption failed")
				os.Exit(util.ExitDecryptFailed)
				return nil
			}

			// Write plaintext.
			if err := os.WriteFile(outFile, plaintext, 0o600); err != nil {
				return fmt.Errorf("write output: %w", err)
			}

			// Output.
			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle": inFile,
					"output": outFile,
					"size":   len(plaintext),
				})
			default:
				printer.Human("Decrypted: %s", inFile)
				printer.Human("Output:    %s", outFile)
				printer.Human("Size:      %d bytes", len(plaintext))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output plaintext path (required)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to the decryption key (required)")
	cmd.Flags().StringVar(&aadStr, "aad", "", "additional authenticated data (overrides manifest AAD)")

	return cmd
}
