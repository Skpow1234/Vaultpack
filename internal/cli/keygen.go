package cli

import (
	"fmt"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var (
		outPrefix string
		algo      string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a signing key pair",
		Long:  "Generate a new signing key pair for signing and verifying .vpack bundles.\n\nSupported algorithms: ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096.\nKeys are saved in PEM format (PKCS#8 private, PKIX public).",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if outPrefix == "" {
				return fmt.Errorf("--out is required (e.g. --out signing)")
			}
			if !crypto.SupportedSignAlgo(algo) {
				return fmt.Errorf("unsupported signing algorithm %q; supported: ed25519, ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096", algo)
			}

			privPath := outPrefix
			if !strings.HasSuffix(privPath, ".key") {
				privPath = outPrefix + ".key"
			}
			pubPath := strings.TrimSuffix(privPath, ".key") + ".pub"

			privPEM, pubPEM, err := crypto.GenerateSigningKeys(algo)
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}

			if err := crypto.SaveKeyPEM(privPath, privPEM, 0o600); err != nil {
				return fmt.Errorf("save private key: %w", err)
			}
			if err := crypto.SaveKeyPEM(pubPath, pubPEM, 0o644); err != nil {
				return fmt.Errorf("save public key: %w", err)
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"private_key": privPath,
					"public_key":  pubPath,
					"algorithm":   algo,
					"format":      "pem",
				})
			default:
				printer.Human("Generated %s signing key pair:", algo)
				printer.Human("  Private: %s (PEM/PKCS#8)", privPath)
				printer.Human("  Public:  %s (PEM/PKIX)", pubPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outPrefix, "out", "", "output path prefix (e.g. 'signing' produces signing.key + signing.pub)")
	cmd.Flags().StringVar(&algo, "algo", crypto.SignAlgoEd25519, "signing algorithm: ed25519, ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096")

	return cmd
}
