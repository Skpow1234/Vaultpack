package cli

import (
	"fmt"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var outPrefix string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing key pair",
		Long:  "Generate a new Ed25519 private/public key pair for signing and verifying .vpack bundles.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if outPrefix == "" {
				return fmt.Errorf("--out is required (e.g. --out signing)")
			}

			privPath := outPrefix
			if !strings.HasSuffix(privPath, ".key") {
				privPath = outPrefix + ".key"
			}
			pubPath := strings.TrimSuffix(privPath, ".key") + ".pub"

			priv, pub, err := crypto.GenerateSigningKeyPair()
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}

			if err := crypto.SaveSigningKey(privPath, priv); err != nil {
				return fmt.Errorf("save private key: %w", err)
			}
			if err := crypto.SavePublicKey(pubPath, pub); err != nil {
				return fmt.Errorf("save public key: %w", err)
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"private_key": privPath,
					"public_key":  pubPath,
					"algorithm":   "ed25519",
				})
			default:
				printer.Human("Generated Ed25519 signing key pair:")
				printer.Human("  Private: %s", privPath)
				printer.Human("  Public:  %s", pubPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outPrefix, "out", "", "output path prefix (e.g. 'signing' produces signing.key + signing.pub)")

	return cmd
}
