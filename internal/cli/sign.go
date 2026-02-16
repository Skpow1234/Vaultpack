package cli

import (
	"bytes"
	"fmt"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		inFile      string
		signingPriv string
		algo        string
	)

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a .vpack bundle",
		Long:  "Add a detached signature to a .vpack bundle.\n\nThe signature covers the canonical manifest and the SHA-256 of the payload.\nSupported algorithms: ed25519 (default), ecdsa-p256, ecdsa-p384, rsa-pss-2048, rsa-pss-4096, ml-dsa-65, ml-dsa-87.\nThe algorithm is auto-detected from the key if --algo is not specified.",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpSign, inFile, inFile, "", "", err == nil, errMsg)
			}()

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

			// Load signing key (auto-detects algorithm from key format).
			privKey, detectedAlgo, err := crypto.LoadPrivateKey(signingPriv)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}

			// If --algo was explicitly set, validate it matches the key.
			signAlgo := detectedAlgo
			if cmd.Flags().Changed("algo") {
				if algo != detectedAlgo {
					return fmt.Errorf("--algo %q does not match key type %q from %s", algo, detectedAlgo, signingPriv)
				}
				signAlgo = algo
			}

			// Store signing algo and timestamp in manifest BEFORE computing canonical form.
			br.Manifest.SignatureAlgo = &signAlgo
			ts := time.Now().UTC().Format(time.RFC3339)
			br.Manifest.SignedAt = &ts

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
			sig, err := crypto.SignMessage(privKey, signAlgo, sigMsg)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}

			// Re-write the bundle with the signature and updated manifest.
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
					"algorithm": signAlgo,
					"signed_at": ts,
					"sig_b64":   util.B64Encode(sig),
				})
			default:
				printer.Human("Signed:    %s", inFile)
				printer.Human("Algo:      %s", signAlgo)
				printer.Human("Timestamp: %s", ts)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to sign (required)")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to private key (required)")
	cmd.Flags().StringVar(&algo, "algo", "", "signing algorithm (auto-detected from key if omitted)")

	return cmd
}
