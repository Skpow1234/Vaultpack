package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/spf13/cobra"
)

func newInspectCmd() *cobra.Command {
	var inFile string

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show manifest details of a .vpack bundle",
		Long:  "Open a .vpack bundle and display its manifest in human-readable or JSON format.\n\nAzure: use az://container/blob.vpack for --in.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}

			// Azure: download bundle from blob if az:// URI.
			displayName := inFile
			if isAzure(inFile) {
				tmpPath, err := azureDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from Azure: %w", err)
				}
				defer os.Remove(tmpPath)
				inFile = tmpPath
			}
			_ = displayName

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
				printer.Human("Bundle:     %s", displayName)
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
			if m.Encryption.IsChunked() {
				printer.Human("  Chunked:  yes (%d byte chunks)", *m.Encryption.ChunkSize)
			}
			if m.Encryption.KDF != nil {
				printer.Human("")
				printer.Human("Key Derivation:")
				printer.Human("  KDF:      %s", m.Encryption.KDF.Algo)
				printer.Human("  Salt:     %s", m.Encryption.KDF.SaltB64)
				switch m.Encryption.KDF.Algo {
				case "argon2id":
					printer.Human("  Time:     %d", m.Encryption.KDF.Time)
					printer.Human("  Memory:   %d KiB", m.Encryption.KDF.Memory)
					printer.Human("  Threads:  %d", m.Encryption.KDF.Threads)
				case "scrypt":
					printer.Human("  N:        %d", m.Encryption.KDF.N)
					printer.Human("  r:        %d", m.Encryption.KDF.R)
					printer.Human("  p:        %d", m.Encryption.KDF.P)
				case "pbkdf2-sha256":
					printer.Human("  Iter:     %d", m.Encryption.KDF.Iterations)
				}
			}
			if m.Encryption.Hybrid != nil {
				printer.Human("")
				printer.Human("Hybrid Encryption:")
				printer.Human("  Scheme:   %s", m.Encryption.Hybrid.Scheme)
				if m.Encryption.Hybrid.EphemeralPubKeyB64 != "" {
					printer.Human("  Eph.Key:  %s", m.Encryption.Hybrid.EphemeralPubKeyB64)
				}
				if m.Encryption.Hybrid.WrappedDEKB64 != "" {
					trunc := m.Encryption.Hybrid.WrappedDEKB64
					if len(trunc) > 32 {
						trunc = trunc[:32]
					}
					printer.Human("  Wrapped:  %s...", trunc)
				}
				if m.Encryption.Hybrid.RecipientFingerprintB64 != "" {
					printer.Human("  Recip.FP: %s", m.Encryption.Hybrid.RecipientFingerprintB64)
				}
				if len(m.Encryption.Hybrid.Recipients) > 0 {
					printer.Human("  Recipients: %d", len(m.Encryption.Hybrid.Recipients))
					for i, r := range m.Encryption.Hybrid.Recipients {
						printer.Human("    [%d] Scheme: %s  FP: %s", i, r.Scheme, r.FingerprintB64)
					}
				}
			}
			if m.Compress != nil {
				printer.Human("")
				printer.Human("Compression:")
				printer.Human("  Algo:     %s", m.Compress.Algo)
				printer.Human("  Original: %d bytes", m.Compress.OriginalSize)
			}
			if m.KeySplitting != nil {
				printer.Human("")
				printer.Human("Key Splitting:")
				printer.Human("  Scheme:    %s", m.KeySplitting.Scheme)
				printer.Human("  Threshold: %d-of-%d", m.KeySplitting.Threshold, m.KeySplitting.Total)
			}
			if m.SignatureAlgo != nil {
				printer.Human("")
				printer.Human("Signature:")
				printer.Human("  Algo:     %s", *m.SignatureAlgo)
				if m.SignedAt != nil {
					printer.Human("  Signed:   %s", *m.SignedAt)
				}
			}
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
