package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

func newCombineKeyCmd() *cobra.Command {
	var (
		shareFiles []string
		outFile    string
	)

	cmd := &cobra.Command{
		Use:   "combine-key",
		Short: "Reconstruct a key from K Shamir shares",
		Long: `Reconstruct a symmetric key from K-of-N Shamir shares.

The threshold K is automatically read from the share metadata.
Provide at least K share files; additional shares are accepted but only K are used.

Example:
  vaultpack combine-key --share data.key.share1 --share data.key.share3 --share data.key.share5 --out data.key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if len(shareFiles) == 0 {
				return fmt.Errorf("at least one --share is required")
			}
			if outFile == "" {
				return fmt.Errorf("--out is required")
			}

			// Read and parse all shares.
			shares := make([]*crypto.Share, 0, len(shareFiles))
			for _, path := range shareFiles {
				data, err := os.ReadFile(path)
				if err != nil {
					printer.Error(err, fmt.Sprintf("failed to read share %s", path))
					return err
				}
				s, err := crypto.UnmarshalShare(data)
				if err != nil {
					printer.Error(err, fmt.Sprintf("failed to parse share %s", path))
					return err
				}
				shares = append(shares, s)
			}

			// Threshold is encoded in each share; validate minimum.
			k := int(shares[0].Threshold)
			if len(shares) < k {
				return fmt.Errorf("need at least %d shares (threshold), got %d", k, len(shares))
			}

			// Reconstruct.
			secret, err := crypto.CombineShares(shares)
			if err != nil {
				printer.Error(err, "reconstruction failed")
				return err
			}

			// Write the reconstructed key.
			if err := os.WriteFile(outFile, secret, 0o600); err != nil {
				printer.Error(err, "failed to write output file")
				return err
			}

			if printer.Mode == OutputJSON {
				return printer.JSON(map[string]any{
					"scheme":       "shamir-gf256",
					"shares_used":  len(shares),
					"threshold":    k,
					"output":       outFile,
					"key_len":      len(secret),
				})
			}

			printer.Human("Key reconstructed from %d shares (threshold %d)", len(shares), k)
			printer.Human("Output: %s", outFile)

			return nil
		},
	}

	f := cmd.Flags()
	f.StringArrayVar(&shareFiles, "share", nil, "path to a share file (repeat for each share)")
	f.StringVar(&outFile, "out", "", "output path for reconstructed key")

	return cmd
}
