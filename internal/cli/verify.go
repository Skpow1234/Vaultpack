package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	var (
		inFile string
		pubKey string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a .vpack bundle signature",
		Long:  "Verify the detached signature of a .vpack bundle against the canonical manifest and payload hash.\n\nThe signing algorithm is auto-detected from the manifest's signature_algo field or the public key format.",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpVerify, inFile, "", "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if pubKey == "" {
				return fmt.Errorf("--pubkey is required")
			}

			// Read the full bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			if br.Signature == nil {
				auditLog(audit.OpVerify, inFile, "", "", "", false, "bundle is not signed")
				printer.Error(util.ErrVerifyFailed, "bundle is not signed (no signature.sig)")
				os.Exit(util.ExitVerifyFailed)
				return nil
			}

			// Load public key (auto-detects algorithm).
			pub, keyAlgo, err := crypto.LoadAnyPublicKey(pubKey)
			if err != nil {
				return fmt.Errorf("load public key: %w", err)
			}

			// Determine signing algorithm: prefer manifest field, fall back to key type.
			signAlgo := keyAlgo
			if br.Manifest.SignatureAlgo != nil && *br.Manifest.SignatureAlgo != "" {
				signAlgo = *br.Manifest.SignatureAlgo
			}

			// Rebuild the signing message from the bundle contents.
			canonical, err := bundle.CanonicalManifest(br.Manifest)
			if err != nil {
				return fmt.Errorf("canonicalize manifest: %w", err)
			}

			payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
			if err != nil {
				return fmt.Errorf("hash payload: %w", err)
			}

			sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)

			valid, err := crypto.VerifySignature(pub, signAlgo, sigMsg, br.Signature)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			if !valid {
				auditLog(audit.OpVerify, inFile, "", "", "", false, "signature verification failed")
				printer.Error(util.ErrVerifyFailed, "signature verification failed")
				os.Exit(util.ExitVerifyFailed)
				return nil
			}

			signedAt := ""
			if br.Manifest.SignedAt != nil {
				signedAt = *br.Manifest.SignedAt
			}

			switch printer.Mode {
			case OutputJSON:
				result := map[string]any{
					"bundle":    inFile,
					"verified":  true,
					"algorithm": signAlgo,
				}
				if signedAt != "" {
					result["signed_at"] = signedAt
				}
				return printer.JSON(result)
			default:
				printer.Human("Verified: %s", inFile)
				printer.Human("Algo:     %s", signAlgo)
				if signedAt != "" {
					printer.Human("Signed:   %s", signedAt)
				}
				printer.Human("Signature is valid.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to verify (required)")
	cmd.Flags().StringVar(&pubKey, "pubkey", "", "path to public key (required)")

	return cmd
}
