package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/spf13/cobra"
)

func newBatchInspectCmd() *cobra.Command {
	var (
		srcDir string
	)

	cmd := &cobra.Command{
		Use:   "batch-inspect",
		Short: "Show summary of all .vpack bundles in a directory",
		Long: `Recursively find all .vpack bundles in a directory and display a summary
of each bundle's manifest. Also reads batch-manifest.json if present.

Example:
  vaultpack batch-inspect --dir ./encrypted/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if srcDir == "" {
				return fmt.Errorf("--dir is required")
			}

			// Check for batch-manifest.json.
			bmPath := filepath.Join(srcDir, "batch-manifest.json")
			var bm *BatchManifest
			if data, err := os.ReadFile(bmPath); err == nil {
				bm = &BatchManifest{}
				if err := json.Unmarshal(data, bm); err != nil {
					bm = nil // ignore malformed
				}
			}

			// Collect .vpack files.
			files, err := collectVpackFiles(srcDir)
			if err != nil {
				return fmt.Errorf("scan directory: %w", err)
			}

			if len(files) == 0 {
				printer.Human("No .vpack files found in %s", srcDir)
				return nil
			}

			type bundleInfo struct {
				RelPath string          `json:"rel_path"`
				Version string          `json:"version"`
				Input   bundle.InputMeta `json:"input"`
				Cipher  string          `json:"cipher"`
				Hash    string          `json:"hash_algo"`
				Chunked bool            `json:"chunked"`
				Error   string          `json:"error,omitempty"`
			}

			infos := make([]bundleInfo, 0, len(files))
			for _, f := range files {
				relPath, _ := filepath.Rel(srcDir, f)
				m, _, err := bundle.ReadManifestOnly(f)
				if err != nil {
					infos = append(infos, bundleInfo{
						RelPath: relPath,
						Error:   err.Error(),
					})
					continue
				}
				infos = append(infos, bundleInfo{
					RelPath: relPath,
					Version: m.Version,
					Input:   m.Input,
					Cipher:  m.Encryption.AEAD,
					Hash:    m.Plaintext.Algo,
					Chunked: m.Encryption.IsChunked(),
				})
			}

			switch printer.Mode {
			case OutputJSON:
				result := map[string]any{
					"directory": srcDir,
					"total":     len(infos),
					"bundles":   infos,
				}
				if bm != nil {
					result["batch_manifest"] = bm
				}
				return printer.JSON(result)
			default:
				printer.Human("Directory: %s", srcDir)
				printer.Human("Bundles:   %d", len(infos))
				if bm != nil {
					printer.Human("")
					printer.Human("Batch Manifest:")
					printer.Human("  Operation: %s", bm.Operation)
					printer.Human("  Created:   %s", bm.CreatedAt)
					printer.Human("  Total:     %d (ok: %d, fail: %d)", bm.Total, bm.Succeeded, bm.Failed)
				}
				printer.Human("")
				for _, info := range infos {
					if info.Error != "" {
						printer.Human("  %s  ERROR: %s", info.RelPath, info.Error)
					} else {
						printer.Human("  %s  v=%s  cipher=%s  hash=%s  input=%s (%d B)",
							info.RelPath, info.Version, info.Cipher, info.Hash,
							info.Input.Name, info.Input.Size)
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&srcDir, "dir", "", "directory with .vpack bundles (required)")

	return cmd
}
