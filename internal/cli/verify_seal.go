package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newVerifySealCmd() *cobra.Command {
	var (
		dir  string
		root string
	)

	cmd := &cobra.Command{
		Use:   "verify-seal",
		Short: "Verify Merkle root of .vpack bundles in a directory",
		Long:  "Recompute the Merkle root over all .vpack files in the directory and compare with the expected root. Exits with code 0 if intact, 10 if verification fails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if dir == "" {
				return fmt.Errorf("--dir is required")
			}
			if root == "" {
				return fmt.Errorf("--root is required")
			}

			ok, leaves, err := audit.VerifySealDir(dir, root)
			if err != nil {
				return fmt.Errorf("verify-seal: %w", err)
			}

			auditLog(audit.OpVerifySeal, dir, "", root, "", ok, "")

			if !ok {
				printer.Error(util.ErrVerifyFailed, "Merkle root mismatch: directory was modified since seal")
				os.Exit(util.ExitVerifyFailed)
				return nil
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"dir":   dir,
					"root":  root,
					"valid": true,
					"count": len(leaves),
				})
			default:
				printer.Human("Seal valid: %s", dir)
				printer.Human("Root:       %s", root)
				printer.Human("Bundles:    %d", len(leaves))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "directory containing .vpack bundles (required)")
	cmd.Flags().StringVar(&root, "root", "", "expected Merkle root (hex) from seal (required)")

	return cmd
}
