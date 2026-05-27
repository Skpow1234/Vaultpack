package cli

import (
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

// newRewrapCmd builds the `vaultpack rewrap` command.
//
// Rewrap re-wraps the bundle's Data Encryption Key (DEK) under a new wrapping
// without touching the ciphertext payload. This is the cheap path for rotating
// the KMS key used to protect the DEK: the payload bytes, ciphertext nonce,
// AEAD tag, and plaintext digest are all unchanged, so any prior plaintext
// hashes / payload signatures remain valid as material — only the manifest
// signature must be re-applied.
//
// Currently supported: KMS → KMS (same provider, new key ID). Other modes
// (password, key file, hybrid) do not have a separable "wrapping" layer to
// rewrap independently of the payload; use `vaultpack rotate-key` for those.
func newRewrapCmd() *cobra.Command {
	var (
		inFile      string
		outFile     string
		kmsProvider string
		fromKeyID   string
		toKeyID     string
	)

	cmd := &cobra.Command{
		Use:   "rewrap",
		Short: "Re-wrap the DEK under a new KMS key without decrypting the payload",
		Long: `Re-wrap the Data Encryption Key (DEK) of a .vpack bundle under a new KMS key.

The ciphertext payload is not touched, so this is suitable for KMS key rotation
without requiring access to the plaintext.

The new manifest invalidates any prior signature; re-sign with 'vaultpack sign'.`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			printer := NewPrinter(flagJSON, flagQuiet)
			defer func() {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				auditLog(audit.OpRewrap, inFile, outFile, "", "", err == nil, errMsg)
			}()

			if inFile == "" {
				return fmt.Errorf("--in is required")
			}
			if outFile == "" {
				outFile = inFile
			}
			if kmsProvider == "" {
				return fmt.Errorf("--kms-provider is required (e.g. aws, gcp, azure, mock)")
			}
			if toKeyID == "" {
				return fmt.Errorf("--to-kms-key-id is required")
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
			if err := enforcePolicy(audit.OpRewrap, inFile, br.Manifest); err != nil {
				return err
			}
			if br.Manifest.Encryption.KmsKeyID == "" || br.Manifest.Encryption.KmsWrappedDEKB64 == "" {
				return fmt.Errorf("bundle is not KMS-wrapped; use 'vaultpack rotate-key' to change key/mode")
			}

			if fromKeyID != "" && fromKeyID != br.Manifest.Encryption.KmsKeyID {
				return fmt.Errorf("--from-kms-key-id %q does not match manifest's %q", fromKeyID, br.Manifest.Encryption.KmsKeyID)
			}

			provider := kms.Get(kmsProvider)
			if provider == nil {
				return fmt.Errorf("KMS provider %q not found; available: %v", kmsProvider, kms.Providers())
			}

			wrapped, err := util.B64Decode(br.Manifest.Encryption.KmsWrappedDEKB64)
			if err != nil {
				return fmt.Errorf("decode existing wrapped DEK: %w", err)
			}
			dek, err := provider.UnwrapDEK(wrapped, br.Manifest.Encryption.KmsKeyID)
			if err != nil {
				return fmt.Errorf("KMS unwrap with old key: %w", err)
			}

			newWrapped, err := provider.WrapDEK(dek, toKeyID)
			if err != nil {
				return fmt.Errorf("KMS wrap with new key: %w", err)
			}

			prevHash, err := hashBundleFile(localIn)
			if err != nil {
				return err
			}
			oldKeyID := br.Manifest.Encryption.KmsKeyID
			br.Manifest.Encryption.KmsKeyID = toKeyID
			br.Manifest.Encryption.KmsWrappedDEKB64 = util.B64Encode(newWrapped)
			appendRotation(br.Manifest, prevHash, audit.OpRewrap,
				fmt.Sprintf("kms %s: %s -> %s", kmsProvider, oldKeyID, toKeyID))

			manifestBytes, err := bundle.MarshalManifest(br.Manifest)
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}
			// Write to local path; if --out is remote, upload below.
			localOut := outFile
			remoteOut := ""
			if isRemoteURI(outFile) {
				remoteOut = outFile
				tmp, terr := os.CreateTemp("", "vaultpack-rewrap-*.vpack")
				if terr != nil {
					return fmt.Errorf("create temp output: %w", terr)
				}
				tmp.Close()
				localOut = tmp.Name()
				defer os.Remove(tmp.Name())
			}
			if err := bundle.Write(&bundle.WriteParams{
				OutputPath:    localOut,
				Ciphertext:    br.Ciphertext,
				ManifestBytes: manifestBytes,
			}); err != nil {
				return fmt.Errorf("write bundle: %w", err)
			}
			if remoteOut != "" {
				if err := remoteUploadFile(localOut, remoteOut); err != nil {
					return fmt.Errorf("upload bundle: %w", err)
				}
			}

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"bundle":       outFile,
					"operation":    audit.OpRewrap,
					"kms_provider": kmsProvider,
					"old_key":      oldKeyID,
					"new_key":      toKeyID,
					"signed":       false,
				})
			default:
				printer.Human("Rewrap:    %s", outFile)
				printer.Human("Old KMS:   %s", oldKeyID)
				printer.Human("New KMS:   %s", toKeyID)
				printer.Human("Signature: cleared; run 'vaultpack sign' to re-sign.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "output bundle path (defaults to --in, i.e. in-place)")
	cmd.Flags().StringVar(&kmsProvider, "kms-provider", "", "KMS provider for both unwrap and rewrap (aws|gcp|azure|mock)")
	cmd.Flags().StringVar(&fromKeyID, "from-kms-key-id", "", "expected KMS key ID currently wrapping the DEK (optional sanity check)")
	cmd.Flags().StringVar(&toKeyID, "to-kms-key-id", "", "new KMS key ID to wrap the DEK under (required)")

	return cmd
}
