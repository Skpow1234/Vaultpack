package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/spf13/cobra"
)

func newSealCmd() *cobra.Command {
	var (
		dir    string
		rootOut string
	)

	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Create a Merkle root over all .vpack bundles in a directory",
		Long:  "Hash every .vpack file in the directory and compute a deterministic Merkle root. Use verify-seal to later verify that no bundles were added, removed, or modified.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if dir == "" {
				return fmt.Errorf("--dir is required")
			}

			rootHex, leaves, err := audit.SealDir(dir)
			if err != nil {
				return fmt.Errorf("seal: %w", err)
			}

			if rootOut != "" {
				if err := os.WriteFile(rootOut, []byte(rootHex+"\n"), 0o644); err != nil {
					return fmt.Errorf("write root file: %w", err)
				}
			}

			auditLog(audit.OpSeal, dir, rootOut, rootHex, "", true, "")

			switch printer.Mode {
			case OutputJSON:
				items := make([]map[string]string, len(leaves))
				for i, l := range leaves {
					items[i] = map[string]string{"path": l.Path, "hash": fmt.Sprintf("%x", l.Hash)}
				}
				return printer.JSON(map[string]any{
					"dir":   dir,
					"root":  rootHex,
					"count": len(leaves),
					"files": items,
				})
			default:
				printer.Human("Sealed directory: %s", dir)
				printer.Human("Merkle root:     %s", rootHex)
				printer.Human("Bundles:        %d", len(leaves))
				if rootOut != "" {
					printer.Human("Root saved to:  %s", rootOut)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "directory containing .vpack bundles (required)")
	cmd.Flags().StringVar(&rootOut, "out", "", "write Merkle root (hex) to this file")

	return cmd
}
