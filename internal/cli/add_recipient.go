package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

// newAddRecipientCmd builds the `vaultpack add-recipient` command.
//
// Given a bundle that uses hybrid encryption, unwrap the DEK with one of the
// existing recipients' private keys and re-wrap it for one or more new
// recipient public keys. A single-recipient bundle is upgraded in place to
// multi-recipient form.
//
// The payload is untouched. The previous manifest signature is cleared.
func newAddRecipientCmd() *cobra.Command {
	var (
		inFile       string
		outFile      string
		privKeyFile  string
		newRecipients []string
	)

	cmd := &cobra.Command{
		Use:   "add-recipient",
		Short: "Add one or more recipients to an existing hybrid bundle",
		Long: `Add one or more public-key recipients to an existing hybrid-encrypted .vpack bundle.

You must provide --privkey for an existing recipient (used to unwrap the DEK);
the unwrapped DEK is then re-wrapped under each --recipient public key and
appended to the manifest. The ciphertext is unchanged.

A single-recipient bundle is converted in-place to multi-recipient form. The
previous manifest signature is cleared; re-sign with 'vaultpack sign'.`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpAddRecipient, inFile, outFile, "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if outFile == "" {
				outFile = inFile
			}
			if privKeyFile == "" {
				return fmt.Errorf("--privkey is required (existing recipient's private key to unwrap the DEK)")
			}
			if len(newRecipients) == 0 {
				return fmt.Errorf("at least one --recipient is required")
			}

			localIn, cleanup, err := resolveBundlePath(inFile)
			if err != nil {
				return fmt.Errorf("resolve input: %w", err)
			}
			if cleanup != nil {
				defer cleanup()
			}

			br, err := bundle.Read(localIn)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}
			h := br.Manifest.Encryption.Hybrid
			if h == nil {
				return fmt.Errorf("bundle is not hybrid-encrypted; add-recipient requires --recipient at protect time")
			}

			// Unwrap the DEK using the provided private key.
			dek, _, err := unwrapHybridDEK(h, privKeyFile)
			if err != nil {
				return err
			}

			// Build the new recipient set. If the bundle was single-recipient,
			// promote the existing single entry into the Recipients list first
			// so the new shape is uniformly multi-recipient.
			recipientEntries := append([]bundle.RecipientEntry(nil), h.Recipients...)
			if len(recipientEntries) == 0 && (h.WrappedDEKB64 != "" || h.EphemeralPubKeyB64 != "") {
				recipientEntries = append(recipientEntries, bundle.RecipientEntry{
					Scheme:             h.Scheme,
					FingerprintB64:     h.RecipientFingerprintB64,
					EphemeralPubKeyB64: h.EphemeralPubKeyB64,
					WrappedDEKB64:      h.WrappedDEKB64,
				})
			}

			addedFPs := make([]string, 0, len(newRecipients))
			for _, rp := range newRecipients {
				scheme, err := crypto.DetectHybridScheme(rp)
				if err != nil {
					return fmt.Errorf("detect scheme for %s: %w", rp, err)
				}
				fp, err := crypto.RecipientKeyFingerprint(rp)
				if err != nil {
					return fmt.Errorf("recipient fingerprint %s: %w", rp, err)
				}
				if recipientByFingerprint(recipientEntries, fp) >= 0 {
					return fmt.Errorf("recipient %s is already in the bundle (fingerprint %s)", rp, fp)
				}
				entry := bundle.RecipientEntry{Scheme: scheme, FingerprintB64: fp}
				if plugin.GlobalRegistry().KEMScheme(scheme) != "" {
					pres, err := plugin.GlobalRegistry().Encapsulate(scheme, rp, dek)
					if err != nil {
						return fmt.Errorf("plugin wrap for %s: %w", rp, err)
					}
					entry.EphemeralPubKeyB64 = pres.EphemeralB64
					entry.WrappedDEKB64 = pres.WrappedDEKB64
				} else {
					result, err := crypto.HybridEncapsulateWithDEK(scheme, rp, dek)
					if err != nil {
						return fmt.Errorf("wrap DEK for %s: %w", rp, err)
					}
					if len(result.EphemeralPublicKey) > 0 {
						entry.EphemeralPubKeyB64 = util.B64Encode(result.EphemeralPublicKey)
					}
					if len(result.WrappedDEK) > 0 {
						entry.WrappedDEKB64 = util.B64Encode(result.WrappedDEK)
					}
				}
				recipientEntries = append(recipientEntries, entry)
				addedFPs = append(addedFPs, fp)
			}

			// Replace Hybrid with the new multi-recipient shape.
			br.Manifest.Encryption.Hybrid = &bundle.HybridMeta{
				Scheme:     "multi-recipient",
				Recipients: recipientEntries,
			}

			prevHash, err := hashBundleFile(localIn)
			if err != nil {
				return err
			}
			notes := fmt.Sprintf("added %d recipient(s)", len(addedFPs))
			appendRotation(br.Manifest, prevHash, audit.OpAddRecipient, notes)

			manifestBytes, err := bundle.MarshalManifest(br.Manifest)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}
			if err := writeBundleMaybeRemote(outFile, br.Ciphertext, manifestBytes); err != nil {
				return err
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":            outFile,
					"operation":         audit.OpAddRecipient,
					"added_fingerprints": addedFPs,
					"total_recipients":  len(recipientEntries),
					"signed":            false,
				})
			default:
				printer.Human("Add recipients: %s", outFile)
				for _, fp := range addedFPs {
					printer.Human("  + %s", fp)
				}
				printer.Human("Total recipients: %d", len(recipientEntries))
				printer.Human("Signature: cleared; run 'vaultpack sign' to re-sign.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output bundle path (defaults to --in)")
	cmd.Flags().StringVar(&privKeyFile, "privkey", "", "private key of an existing recipient (to unwrap the DEK) (required)")
	cmd.Flags().StringArrayVar(&newRecipients, "recipient", nil, "public key path of a new recipient (can be repeated)")

	return cmd
}

// unwrapHybridDEK tries every recipient entry in h against privKeyFile and
// returns the DEK plus the fingerprint of the matching recipient.
func unwrapHybridDEK(h *bundle.HybridMeta, privKeyFile string) ([]byte, string, error) {
	if h == nil {
		return nil, "", fmt.Errorf("manifest has no hybrid section")
	}
	// Single-recipient bundle.
	if len(h.Recipients) == 0 {
		ephPub, _ := util.B64Decode(h.EphemeralPubKeyB64)
		wrapped, _ := util.B64Decode(h.WrappedDEKB64)
		var dek []byte
		var err error
		if plugin.GlobalRegistry().KEMScheme(h.Scheme) != "" {
			dek, err = plugin.GlobalRegistry().Decapsulate(h.Scheme, privKeyFile, h.EphemeralPubKeyB64, h.WrappedDEKB64)
		} else {
			dek, err = crypto.HybridDecapsulate(h.Scheme, privKeyFile, ephPub, wrapped)
		}
		if err != nil {
			return nil, "", fmt.Errorf("decapsulate DEK: %w", err)
		}
		return dek, h.RecipientFingerprintB64, nil
	}
	// Multi-recipient bundle: try each entry until one succeeds.
	var lastErr error
	for _, re := range h.Recipients {
		ephPub, _ := util.B64Decode(re.EphemeralPubKeyB64)
		wrapped, _ := util.B64Decode(re.WrappedDEKB64)
		var dek []byte
		var err error
		if plugin.GlobalRegistry().KEMScheme(re.Scheme) != "" {
			dek, err = plugin.GlobalRegistry().Decapsulate(re.Scheme, privKeyFile, re.EphemeralPubKeyB64, re.WrappedDEKB64)
		} else {
			dek, err = crypto.HybridDecapsulateWrappedDEK(re.Scheme, privKeyFile, ephPub, wrapped)
		}
		if err == nil {
			return dek, re.FingerprintB64, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no matching recipient in bundle")
	}
	return nil, "", fmt.Errorf("private key does not match any recipient: %w", lastErr)
}

// recipientByFingerprint returns the index of the recipient with the given fingerprint, or -1.
func recipientByFingerprint(entries []bundle.RecipientEntry, fp string) int {
	for i, e := range entries {
		if e.FingerprintB64 == fp {
			return i
		}
	}
	return -1
}

// writeBundleMaybeRemote writes a bundle locally, then uploads to a remote URI if applicable.
func writeBundleMaybeRemote(outURI string, ciphertext, manifestBytes []byte) error {
	localOut := outURI
	remoteOut := ""
	if isRemoteURI(outURI) {
		remoteOut = outURI
		tmp, err := os.CreateTemp("", "vaultpack-rot-*.vpack")
		if err != nil {
			return fmt.Errorf("create temp output: %w", err)
		}
		tmp.Close()
		localOut = tmp.Name()
		defer os.Remove(tmp.Name())
	}
	if err := bundle.Write(&bundle.WriteParams{
		OutputPath:    localOut,
		Ciphertext:    ciphertext,
		ManifestBytes: manifestBytes,
	}); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	if remoteOut != "" {
		if err := remoteUploadFile(localOut, remoteOut); err != nil {
			return fmt.Errorf("upload bundle: %w", err)
		}
	}
	return nil
}
