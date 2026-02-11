package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newHashCmd() *cobra.Command {
	var (
		inFile string
		algo   string
	)

	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Compute a hash digest for a file",
		Long:  "Compute a cryptographic hash (e.g. SHA-256) of the input file and print the result.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if !crypto.SupportedHashAlgo(algo) {
				printer.Error(util.ErrUnsupportedAlgorithm, fmt.Sprintf("algorithm %q is not supported", algo))
				os.Exit(util.ExitUnsupportedVersion)
				return nil
			}

			f, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("open input file: %w", err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				return fmt.Errorf("stat input file: %w", err)
			}

			digest, err := crypto.HashReader(f, algo)
			if err != nil {
				return fmt.Errorf("hash: %w", err)
			}

			digestB64 := util.B64Encode(digest)

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"file":       inFile,
					"algo":       algo,
					"digest_b64": digestB64,
					"size":       info.Size(),
				})
			default:
				printer.Human("File:   %s", inFile)
				printer.Human("Algo:   %s", algo)
				printer.Human("Digest: %s", digestB64)
				printer.Human("Size:   %d bytes", info.Size())
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input file to hash (required)")
	cmd.Flags().StringVar(&algo, "algo", "sha256", "hash algorithm (default: sha256)")

	return cmd
}
