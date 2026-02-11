package cli

import (
	"bytes"
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		inFile      string
		signingPriv string
	)

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a .vpack bundle",
		Long:  "Add a detached Ed25519 signature to a .vpack bundle. The signature covers the canonical manifest and the SHA-256 of the payload.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if signingPriv == "" {
				return fmt.Errorf("--signing-priv is required")
			}

			// Read the full bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			// Load signing key.
			privKey, err := crypto.LoadSigningKey(signingPriv)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}

			// Build the signing message: canonical manifest + SHA-256(payload).
			canonical, err := bundle.CanonicalManifest(br.Manifest)
			if err != nil {
				return fmt.Errorf("canonicalize manifest: %w", err)
			}

			payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
			if err != nil {
				return fmt.Errorf("hash payload: %w", err)
			}

			sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
			sig := crypto.Sign(privKey, sigMsg)

			// Re-write the bundle with the signature included.
			manifestBytes, err := bundle.MarshalManifest(br.Manifest)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}

			err = bundle.Write(&bundle.WriteParams{
				OutputPath:    inFile,
				Ciphertext:    br.Ciphertext,
				ManifestBytes: manifestBytes,
				Signature:     sig,
			})
			if err != nil {
				return fmt.Errorf("write signed bundle: %w", err)
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":    inFile,
					"signed":    true,
					"algorithm": "ed25519",
					"sig_b64":   util.B64Encode(sig),
				})
			default:
				printer.Human("Signed: %s", inFile)
				printer.Human("Algo:   ed25519")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to sign (required)")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to Ed25519 private key (required)")

	return cmd
}
