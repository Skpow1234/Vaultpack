package cli

import (
	"bytes"
	"fmt"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
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

			var signAlgo string
			var sig []byte

			// Plugin sign: require --algo and use plugin binary.
			if cmd.Flags().Changed("algo") && plugin.GlobalRegistry().SignAlgo(algo) != "" {
				signAlgo = algo
				br.Manifest.SignatureAlgo = &signAlgo
				ts := time.Now().UTC().Format(time.RFC3339)
				br.Manifest.SignedAt = &ts
				canonical, err := bundle.CanonicalManifest(br.Manifest)
				if err != nil {
					return fmt.Errorf("canonicalize manifest: %w", err)
				}
				payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
				if err != nil {
					return fmt.Errorf("hash payload: %w", err)
				}
				sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
				sig, err = plugin.GlobalRegistry().Sign(signAlgo, signingPriv, sigMsg)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}
			} else {
				// Load signing key (auto-detects algorithm from key format).
				privKey, detectedAlgo, err := crypto.LoadPrivateKey(signingPriv)
				if err != nil {
					return fmt.Errorf("load signing key: %w", err)
				}
				signAlgo = detectedAlgo
				if cmd.Flags().Changed("algo") {
					if algo != detectedAlgo {
						return fmt.Errorf("--algo %q does not match key type %q from %s", algo, detectedAlgo, signingPriv)
					}
					signAlgo = algo
				}
				br.Manifest.SignatureAlgo = &signAlgo
				ts := time.Now().UTC().Format(time.RFC3339)
				br.Manifest.SignedAt = &ts
				canonical, err := bundle.CanonicalManifest(br.Manifest)
				if err != nil {
					return fmt.Errorf("canonicalize manifest: %w", err)
				}
				payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
				if err != nil {
					return fmt.Errorf("hash payload: %w", err)
				}
				sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
				sig, err = crypto.SignMessage(privKey, signAlgo, sigMsg)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}
			}

			ts := ""
			if br.Manifest.SignedAt != nil {
				ts = *br.Manifest.SignedAt
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
				if ts != "" {
					printer.Human("Timestamp: %s", ts)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to sign (required)")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to private key (required)")
	cmd.Flags().StringVar(&algo, "algo", "", "signing algorithm (auto-detected from key if omitted)")

	return cmd
}
