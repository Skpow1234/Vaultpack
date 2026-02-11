package cli

import (
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/spf13/cobra"
)

func newInspectCmd() *cobra.Command {
	var inFile string

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show manifest details of a .vpack bundle",
		Long:  "Open a .vpack bundle and display its manifest in human-readable or JSON format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}

			m, rawBytes, err := bundle.ReadManifestOnly(inFile)
			if err != nil {
				return fmt.Errorf("read manifest: %w", err)
			}

			switch printer.Mode {
			case OutputJSON:
				// Output the raw manifest JSON directly for fidelity.
				_, err := printer.Writer.Write(rawBytes)
				return err
			default:
				printer.Human("Bundle:     %s", inFile)
				printer.Human("Version:    %s", m.Version)
				printer.Human("Created:    %s", m.CreatedAt)
				printer.Human("")
				printer.Human("Input:")
				printer.Human("  Name:     %s", m.Input.Name)
				printer.Human("  Size:     %d bytes", m.Input.Size)
				printer.Human("")
				printer.Human("Plaintext Hash:")
				printer.Human("  Algo:     %s", m.Plaintext.Algo)
				printer.Human("  Digest:   %s", m.Plaintext.DigestB64)
				printer.Human("")
				printer.Human("Encryption:")
				printer.Human("  AEAD:     %s", m.Encryption.AEAD)
				printer.Human("  Nonce:    %s", m.Encryption.NonceB64)
				printer.Human("  Tag:      %s", m.Encryption.TagB64)
				if m.Encryption.AADB64 != nil {
					printer.Human("  AAD:      %s", *m.Encryption.AADB64)
				} else {
					printer.Human("  AAD:      (none)")
				}
				printer.Human("  Key ID:   %s:%s", m.Encryption.KeyID.Algo, m.Encryption.KeyID.DigestB64)
				printer.Human("")
				printer.Human("Ciphertext:")
				printer.Human("  Size:     %d bytes", m.Ciphertext.Size)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")

	return cmd
}
