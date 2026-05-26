package cli

import (
	"fmt"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/spf13/cobra"
)

// newRemoveRecipientCmd builds the `vaultpack remove-recipient` command.
//
// Drops one or more RecipientEntry blocks from a multi-recipient hybrid
// manifest. The ciphertext and DEK are unchanged, so anyone who previously
// had access and retained a copy of the bundle's bytes can still decrypt
// them: to truly revoke, follow `remove-recipient` with `rotate-key`.
//
// The previous manifest signature is cleared.
func newRemoveRecipientCmd() *cobra.Command {
	var (
		inFile        string
		outFile       string
		recipientPubs []string
		fingerprints  []string
	)

	cmd := &cobra.Command{
		Use:   "remove-recipient",
		Short: "Remove one or more recipients from a multi-recipient hybrid bundle",
		Long: `Remove one or more public-key recipients from an existing multi-recipient .vpack bundle.

Recipients can be identified by --recipient <pubkey.pem> (the file's
fingerprint is computed automatically) or --fingerprint <b64>.

The ciphertext and DEK are NOT changed by this command. Anyone who previously
held access to the DEK can still decrypt the bundle's bytes if they kept them.
To truly revoke a recipient, follow with 'vaultpack rotate-key'.

The previous manifest signature is cleared; re-sign with 'vaultpack sign'.`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpRemoveRecipient, inFile, outFile, "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if outFile == "" {
				outFile = inFile
			}
			if len(recipientPubs) == 0 && len(fingerprints) == 0 {
				return fmt.Errorf("at least one --recipient or --fingerprint is required")
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
			if h == nil || len(h.Recipients) == 0 {
				return fmt.Errorf("bundle is not multi-recipient; nothing to remove")
			}

			// Collect target fingerprints.
			targets := make(map[string]bool)
			for _, rp := range recipientPubs {
				fp, err := crypto.RecipientKeyFingerprint(rp)
				if err != nil {
					return fmt.Errorf("fingerprint %s: %w", rp, err)
				}
				targets[fp] = true
			}
			for _, fp := range fingerprints {
				targets[fp] = true
			}

			kept := make([]bundle.RecipientEntry, 0, len(h.Recipients))
			removedFPs := make([]string, 0)
			for _, e := range h.Recipients {
				if targets[e.FingerprintB64] {
					removedFPs = append(removedFPs, e.FingerprintB64)
					continue
				}
				kept = append(kept, e)
			}
			if len(removedFPs) == 0 {
				return fmt.Errorf("no matching recipients found in bundle")
			}
			if len(kept) == 0 {
				return fmt.Errorf("refusing to remove every recipient (would orphan the bundle)")
			}
			h.Recipients = kept

			prevHash, err := hashBundleFile(localIn)
			if err != nil {
				return err
			}
			notes := fmt.Sprintf("removed %d recipient(s)", len(removedFPs))
			appendRotation(br.Manifest, prevHash, audit.OpRemoveRecipient, notes)

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
					"bundle":             outFile,
					"operation":          audit.OpRemoveRecipient,
					"removed_fingerprints": removedFPs,
					"remaining_recipients": len(kept),
					"signed":             false,
				})
			default:
				printer.Human("Remove recipients: %s", outFile)
				for _, fp := range removedFPs {
					printer.Human("  - %s", fp)
				}
				printer.Human("Remaining: %d recipient(s)", len(kept))
				printer.Human("WARNING: anyone with a prior copy can still decrypt; run 'vaultpack rotate-key' to fully revoke.")
				printer.Human("Signature: cleared; run 'vaultpack sign' to re-sign.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output bundle path (defaults to --in)")
	cmd.Flags().StringArrayVar(&recipientPubs, "recipient", nil, "public key path of recipient to remove (can be repeated)")
	cmd.Flags().StringArrayVar(&fingerprints, "fingerprint", nil, "base64 fingerprint of recipient to remove (can be repeated)")

	return cmd
}
