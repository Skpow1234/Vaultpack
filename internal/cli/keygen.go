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
		Short: "Generate a key pair",
		Long: "Generate a new key pair for signing, verifying, or hybrid encryption.\n\n" +
			"Signing algorithms: ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096, ml-dsa-65, ml-dsa-87.\n" +
			"Hybrid encryption: x25519, ecies-p256, rsa-oaep-2048, rsa-oaep-4096, ml-kem-768, ml-kem-1024.\n" +
			"Keys are saved in PEM format (PKCS#8 private, PKIX public; ML-KEM/ML-DSA use custom PEM types).",
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

			var privPEM, pubPEM []byte
			var err error
			var purpose string

			// Check if it's a signing algorithm or hybrid scheme.
			if crypto.SupportedSignAlgo(algo) {
				privPEM, pubPEM, err = crypto.GenerateSigningKeys(algo)
				purpose = "signing"
			} else if crypto.SupportedHybridScheme(algo) {
				privPEM, pubPEM, err = crypto.GenerateHybridKeys(algo)
				purpose = "encryption"
			} else {
				return fmt.Errorf("unsupported algorithm %q; signing: ed25519, ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096, ml-dsa-65, ml-dsa-87; encryption: x25519, ecies-p256, rsa-oaep-2048, rsa-oaep-4096, ml-kem-768, ml-kem-1024", algo)
			}
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
					"purpose":     purpose,
					"format":      "pem",
				})
			default:
				printer.Human("Generated %s %s key pair:", algo, purpose)
				printer.Human("  Private: %s (PEM/PKCS#8)", privPath)
				printer.Human("  Public:  %s (PEM/PKIX)", pubPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outPrefix, "out", "", "output path prefix (e.g. 'signing' produces signing.key + signing.pub)")
	cmd.Flags().StringVar(&algo, "algo", crypto.SignAlgoEd25519, "algorithm (see --help for full list)")

	return cmd
}
