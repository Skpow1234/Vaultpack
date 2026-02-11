package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

func newSplitKeyCmd() *cobra.Command {
	var (
		inFile    string
		outDir    string
		shares    int
		threshold int
	)

	cmd := &cobra.Command{
		Use:   "split-key",
		Short: "Split a key file into N Shamir shares (K-of-N threshold)",
		Long: `Split a symmetric key file into N shares using Shamir's Secret Sharing over GF(256).

At least K shares are required to reconstruct the original key; fewer than K
shares reveal zero information about the secret.

Example:
  vaultpack split-key --in data.key --shares 5 --threshold 3
  # produces data.key.share1 … data.key.share5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if shares < 2 || shares > 255 {
				return fmt.Errorf("--shares must be in [2..255]")
			}
			if threshold < 2 || threshold > shares {
				return fmt.Errorf("--threshold must be in [2..shares]")
			}

			// Read the key file (raw bytes, not the parsed key).
			secret, err := os.ReadFile(inFile)
			if err != nil {
				printer.Error(err, "failed to read key file")
				return err
			}

			// Split.
			shareSlice, err := crypto.SplitSecret(secret, shares, threshold)
			if err != nil {
				printer.Error(err, "split failed")
				return err
			}

			// Determine output directory.
			dir := outDir
			if dir == "" {
				dir = filepath.Dir(inFile)
			}
			baseName := filepath.Base(inFile)

			// Write share files.
			paths := make([]string, len(shareSlice))
			for _, s := range shareSlice {
				name := fmt.Sprintf("%s.share%d", baseName, s.Index)
				p := filepath.Join(dir, name)
				data := crypto.MarshalShare(s)
				if err := os.WriteFile(p, data, 0o600); err != nil {
					printer.Error(err, fmt.Sprintf("failed to write share %d", s.Index))
					return err
				}
				paths[int(s.Index)-1] = p
			}

			if printer.Mode == OutputJSON {
				return printer.JSON(map[string]any{
					"scheme":    "shamir-gf256",
					"threshold": threshold,
					"total":     shares,
					"shares":    paths,
				})
			}

			printer.Human("Split key into %d shares (threshold %d):", shares, threshold)
			for _, p := range paths {
				printer.Human("  %s", p)
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&inFile, "in", "", "path to the key file to split")
	f.StringVar(&outDir, "out-dir", "", "directory for share files (default: same as key file)")
	f.IntVar(&shares, "shares", 5, "total number of shares (N)")
	f.IntVar(&threshold, "threshold", 3, "minimum shares to reconstruct (K)")

	return cmd
}
