package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

func newAttestCmd() *cobra.Command {
	var (
		inFile           string
		outFile          string
		embed            bool
		useTransparency  bool
		signingPriv      string
		rekorURL         string
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

			// Support remote URIs for inspect-only (we need to read manifest + optional hash of payload).
			displayName := inFile
			if isRemoteURI(inFile) {
				tmpPath, err := remoteDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from remote: %w", err)
				}
				defer os.Remove(tmpPath)
				inFile = tmpPath
			}

			m, _, err := bundle.ReadManifestOnly(inFile)
			if err != nil {
				return fmt.Errorf("read manifest: %w", err)
			}

			if err := enforcePolicy(audit.OpAttest, displayName, m); err != nil {
				return err
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

			// M24: optional Rekor upload of the signed provenance. We sign the
			// provBytes with the supplied key and upload a hashedrekord entry.
			// The Rekor metadata is printed but, because attest doesn't always
			// rewrite the bundle, it is not appended to the manifest by default.
			var rekorOut map[string]any
			if useTransparency {
				if signingPriv == "" {
					return fmt.Errorf("--transparency requires --signing-priv")
				}
				signer, signAlgo, err := crypto.LoadPrivateKey(signingPriv)
				if err != nil {
					return fmt.Errorf("load signing key: %w", err)
				}
				if !rekorSupportsAlgo(signAlgo) {
					return fmt.Errorf("transparency requires a Rekor-compatible signing algo; got %q", signAlgo)
				}
				sig, err := crypto.SignMessage(signer, signAlgo, provBytes)
				if err != nil {
					return fmt.Errorf("sign provenance: %w", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				entry, err := uploadToRekor(ctx, rekorUploadOpts{
					RekorURL:   rekorURL,
					PubKey:     crypto.PublicKeyOf(signer),
					Signature:  sig,
					SignedData: provBytes,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("rekor upload: %w", err)
				}
				rekorOut = map[string]any{
					"log_url":         entry.LogURL,
					"log_index":       entry.LogIndex,
					"uuid":            entry.UUID,
					"integrated_time": entry.IntegratedTime,
				}
				// attest doesn't rewrite the manifest by design (it produces
				// a side-car or stdout artifact). The Rekor entry stands alone
				// on the transparency log and the UUID is surfaced to the user
				// so they can record it in their build system. Use
				// `sign --transparency` to bake the entry into the manifest.
			}
			if embed {
				embedPath := inFile
				if displayName != inFile {
					embedPath = displayName // might be az://...; then we can't embed locally
				}
				if isRemoteURI(displayName) {
					return fmt.Errorf("--embed is not supported for remote URIs; use --out to save provenance locally")
				}
				if err := bundle.AddProvenanceToBundle(embedPath, provBytes); err != nil {
					return fmt.Errorf("embed provenance: %w", err)
				}
				auditLog(audit.OpAttest, displayName, embedPath, bundleDigestHex, "", true, "")
				if printer.Mode == OutputJSON {
					out := map[string]any{"provenance": "embedded", "bundle": embedPath}
					if rekorOut != nil {
						out["transparency"] = rekorOut
					}
					return printer.JSON(out)
				}
				printer.Human("Provenance embedded in %s", embedPath)
				if rekorOut != nil {
					printer.Human("Rekor UUID:  %v", rekorOut["uuid"])
					printer.Human("Rekor index: %v", rekorOut["log_index"])
				}
				return nil
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, provBytes, 0o644); err != nil {
					return fmt.Errorf("write provenance: %w", err)
				}
				auditLog(audit.OpAttest, displayName, outFile, bundleDigestHex, "", true, "")
				if printer.Mode == OutputJSON {
					out := map[string]any{"provenance_file": outFile, "bundle": displayName}
					if rekorOut != nil {
						out["transparency"] = rekorOut
					}
					return printer.JSON(out)
				}
				printer.Human("Provenance written to %s", outFile)
				if rekorOut != nil {
					printer.Human("Rekor UUID:  %v", rekorOut["uuid"])
					printer.Human("Rekor index: %v", rekorOut["log_index"])
				}
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
	cmd.Flags().BoolVar(&useTransparency, "transparency", false, "sign the provenance and upload it to a Sigstore Rekor transparency log")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "private key for signing provenance (required with --transparency)")
	cmd.Flags().StringVar(&rekorURL, "rekor-url", "", "Rekor base URL (defaults to https://rekor.sigstore.dev)")

	return cmd
}
