package cli

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/cloud"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/keysource"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		inFile           string
		signingPriv      string
		signingKeySource string
		algo             string
		useTransparency  bool
		rekorURL         string
		keyless          bool
		fulcioURL        string
		oidcTokenFile    string
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
			if keyless {
				if !useTransparency {
					return fmt.Errorf("--keyless requires --transparency")
				}
				if signingPriv != "" || signingKeySource != "" {
					return fmt.Errorf("--keyless cannot be combined with --signing-priv or --signing-key-source")
				}
			} else if signingPriv == "" && signingKeySource == "" {
				return fmt.Errorf("--signing-priv or --signing-key-source is required (or use --keyless)")
			}
			if signingPriv != "" && signingKeySource != "" {
				return fmt.Errorf("--signing-priv and --signing-key-source are mutually exclusive")
			}

			// Remote input (az://, s3://, gs://): download to temp, sign locally,
			// then re-upload the signed bundle. HTTPS is read-only.
			displayName := inFile
			remoteURI := ""
			if isRemoteURI(inFile) {
				if !cloud.IsWritable(inFile) {
					return fmt.Errorf("cannot sign read-only scheme: %q", inFile)
				}
				remoteURI = inFile
				tmpPath, err := remoteDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from remote: %w", err)
				}
				defer os.Remove(tmpPath)
				inFile = tmpPath
			}

			// Read the full bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			if err := enforcePolicy(audit.OpSign, displayName, br.Manifest); err != nil {
				return err
			}

			var signAlgo string
			var sig []byte
			var keylessSess *keylessSession

			switch {
			case keyless:
				// Keyless: ephemeral ECDSA key + Fulcio cert chain.
				kctx, kcancel := context.WithTimeout(context.Background(), 90*time.Second)
				sess, err := startKeylessSession(kctx, fulcioURL, oidcTokenFile)
				kcancel()
				if err != nil {
					return fmt.Errorf("keyless session: %w", err)
				}
				keylessSess = sess
				signAlgo = "ecdsa-p256"
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
				sig, err = crypto.SignMessage(sess.Signer, signAlgo, sigMsg)
				if err != nil {
					return fmt.Errorf("sign (keyless): %w", err)
				}

			case signingKeySource == "" && cmd.Flags().Changed("algo") && plugin.GlobalRegistry().SignAlgo(algo) != "":
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

			default:
				// Load signing key (auto-detects algorithm from key format).
				var (
					privKey      stdcrypto.Signer
					detectedAlgo string
				)
				if signingKeySource != "" {
					keyBytes, err := keysource.ResolvePrivateKey(signingKeySource)
					if err != nil {
						return fmt.Errorf("load signing key source: %w", err)
					}
					privKey, detectedAlgo, err = crypto.ParsePrivateKey(keyBytes)
					if err != nil {
						return fmt.Errorf("parse signing key source: %w", err)
					}
				} else {
					privKey, detectedAlgo, err = crypto.LoadPrivateKey(signingPriv)
					if err != nil {
						return fmt.Errorf("load signing key: %w", err)
					}
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

			// M24: optional Sigstore Rekor transparency upload. Done *after* the
			// signature is computed but *before* the manifest is finalized so the
			// resulting TransparencyEntry is baked into the canonical manifest.
			var trEntry *bundle.TransparencyEntry
			if useTransparency {
				if !rekorSupportsAlgo(signAlgo) {
					return fmt.Errorf("transparency log requires a Rekor-compatible signing algo (ed25519, ecdsa-p256/p384, rsa-pss-2048/4096); got %q", signAlgo)
				}
				if plugin.GlobalRegistry().SignAlgo(signAlgo) != "" {
					return fmt.Errorf("transparency log not supported for plugin signer %q", signAlgo)
				}
				// Resolve the public key (or cert chain for keyless) that Rekor
				// will store and use to verify the signature.
				var pubKey stdcrypto.PublicKey
				var certChainPEM, identity, oidcIssuer string
				if keylessSess != nil {
					pubKey = &keylessSess.Signer.PublicKey
					certChainPEM = keylessSess.ChainPEM
					identity = keylessSess.Identity
					oidcIssuer = keylessSess.Issuer
				} else {
					var signer stdcrypto.Signer
					if signingKeySource != "" {
						keyBytes, err := keysource.ResolvePrivateKey(signingKeySource)
						if err != nil {
							return fmt.Errorf("re-load signing key source for rekor: %w", err)
						}
						signer, _, err = crypto.ParsePrivateKey(keyBytes)
						if err != nil {
							return fmt.Errorf("parse signing key source for rekor: %w", err)
						}
					} else {
						signer, _, err = crypto.LoadPrivateKey(signingPriv)
						if err != nil {
							return fmt.Errorf("re-load signing key for rekor: %w", err)
						}
					}
					pubKey = crypto.PublicKeyOf(signer)
				}
				canonical, err := bundle.CanonicalManifest(br.Manifest)
				if err != nil {
					return fmt.Errorf("canonicalize manifest for rekor: %w", err)
				}
				payloadHash, err := crypto.HashReader(bytes.NewReader(br.Ciphertext), "sha256")
				if err != nil {
					return fmt.Errorf("hash payload for rekor: %w", err)
				}
				sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				entry, err := uploadToRekor(ctx, rekorUploadOpts{
					RekorURL:     rekorURL,
					PubKey:       pubKey,
					Signature:    sig,
					SignedData:   sigMsg,
					CertChainPEM: certChainPEM,
					Identity:     identity,
					OIDCIssuer:   oidcIssuer,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("rekor upload: %w", err)
				}
				trEntry = &entry
				br.Manifest.Transparency = append(br.Manifest.Transparency, entry)
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

			// Re-upload the signed bundle back to its remote URI.
			if remoteURI != "" {
				if err := remoteUploadFile(inFile, remoteURI); err != nil {
					return fmt.Errorf("upload signed bundle to remote: %w", err)
				}
			}

			switch printer.Mode {
			case OutputJSON:
				out := map[string]any{
					"bundle":    displayName,
					"signed":    true,
					"algorithm": signAlgo,
					"signed_at": ts,
					"sig_b64":   util.B64Encode(sig),
				}
				if trEntry != nil {
					out["transparency"] = map[string]any{
						"log_url":         trEntry.LogURL,
						"log_index":       trEntry.LogIndex,
						"uuid":            trEntry.UUID,
						"integrated_time": trEntry.IntegratedTime,
					}
				}
				return printer.JSON(out)
			default:
				printer.Human("Signed:    %s", displayName)
				printer.Human("Algo:      %s", signAlgo)
				if ts != "" {
					printer.Human("Timestamp: %s", ts)
				}
				if trEntry != nil {
					printer.Human("Rekor URL: %s", trEntry.LogURL)
					printer.Human("Rekor UUID:  %s", trEntry.UUID)
					printer.Human("Rekor index: %d", trEntry.LogIndex)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to sign (required)")
	cmd.Flags().StringVar(&signingPriv, "signing-priv", "", "path to private key (required unless --signing-key-source or --keyless)")
	cmd.Flags().StringVar(&signingKeySource, "signing-key-source", "", "signing key source URI (file://, env://, b64://; reserved HSM/keychain schemes)")
	cmd.Flags().StringVar(&algo, "algo", "", "signing algorithm (auto-detected from key if omitted)")
	cmd.Flags().BoolVar(&useTransparency, "transparency", false, "upload the signature to a Sigstore Rekor transparency log")
	cmd.Flags().StringVar(&rekorURL, "rekor-url", "", "Rekor base URL (defaults to https://rekor.sigstore.dev)")
	cmd.Flags().BoolVar(&keyless, "keyless", false, "use ephemeral key + Fulcio cert (requires --transparency and an OIDC token)")
	cmd.Flags().StringVar(&fulcioURL, "fulcio-url", "", "Fulcio base URL (defaults to https://fulcio.sigstore.dev)")
	cmd.Flags().StringVar(&oidcTokenFile, "oidc-token-file", "", "path to a file containing an OIDC ID token (or VAULTPACK_OIDC_TOKEN / SIGSTORE_ID_TOKEN env)")

	return cmd
}
