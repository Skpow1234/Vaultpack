package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/spf13/cobra"
)

func newAttestCmd() *cobra.Command {
	var (
		inFile  string
		outFile string
		embed   bool
	)

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Generate SLSA-style provenance for a .vpack bundle",
		Long:  "Read a .vpack bundle and emit a provenance statement (builder identity, build timestamp, source hash, environment). Use --out to write to a file; use --embed to store provenance.json inside the bundle (rewrites the bundle).",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}

			// Support az:// for inspect-only (we need to read manifest + optional hash of payload).
			displayName := inFile
			if isAzure(inFile) {
				tmpPath, err := azureDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from Azure: %w", err)
				}
				defer os.Remove(tmpPath)
				inFile = tmpPath
			}

			m, _, err := bundle.ReadManifestOnly(inFile)
			if err != nil {
				return fmt.Errorf("read manifest: %w", err)
			}

			// Bundle digest: SHA-256 of the bundle file (local path only).
			bundleDigestHex := ""
			if data, err := os.ReadFile(inFile); err == nil {
				sum := sha256.Sum256(data)
				bundleDigestHex = hex.EncodeToString(sum[:])
			}

			prov := audit.BuildProvenance(
				displayName,
				bundleDigestHex,
				m.Input.Name,
				m.Input.Size,
				m.Plaintext.Algo,
				m.Plaintext.DigestB64,
			)
			provBytes, err := audit.MarshalProvenance(prov)
			if err != nil {
				return fmt.Errorf("marshal provenance: %w", err)
			}

			if embed {
				embedPath := inFile
				if displayName != inFile {
					embedPath = displayName // might be az://...; then we can't embed locally
				}
				if isAzure(displayName) {
					return fmt.Errorf("--embed is not supported for Azure URIs; use --out to save provenance locally")
				}
				if err := bundle.AddProvenanceToBundle(embedPath, provBytes); err != nil {
					return fmt.Errorf("embed provenance: %w", err)
				}
				auditLog(audit.OpAttest, displayName, embedPath, bundleDigestHex, "", true, "")
				if printer.Mode == OutputJSON {
					return printer.JSON(map[string]string{"provenance": "embedded", "bundle": embedPath})
				}
				printer.Human("Provenance embedded in %s", embedPath)
				return nil
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, provBytes, 0o644); err != nil {
					return fmt.Errorf("write provenance: %w", err)
				}
				auditLog(audit.OpAttest, displayName, outFile, bundleDigestHex, "", true, "")
				if printer.Mode == OutputJSON {
					return printer.JSON(map[string]string{"provenance_file": outFile, "bundle": displayName})
				}
				printer.Human("Provenance written to %s", outFile)
				return nil
			}

			// Default: stdout
			auditLog(audit.OpAttest, displayName, "stdout", bundleDigestHex, "", true, "")
			if printer.Mode == OutputJSON {
				_, _ = printer.Writer.Write(provBytes)
				return nil
			}
			_, _ = os.Stdout.Write(provBytes)
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output provenance.json path (default: stdout)")
	cmd.Flags().BoolVar(&embed, "embed", false, "store provenance.json inside the bundle (rewrites bundle)")

	return cmd
}
