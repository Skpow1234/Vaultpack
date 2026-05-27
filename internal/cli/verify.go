package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/transparency"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	var (
		inFile            string
		pubKey            string
		checkTransparency bool
		rekorPubKeyFile   string
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

			// Remote input (az://, s3://, gs://, https://): download to temp file.
			displayName := inFile
			if isRemoteURI(inFile) {
				tmpPath, err := remoteDownload(inFile)
				if err != nil {
					return fmt.Errorf("download from remote: %w", err)
				}
				defer os.Remove(tmpPath)
				inFile = tmpPath
			}
			_ = displayName

			// Read the full bundle.
			br, err := bundle.Read(inFile)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			if err := enforcePolicy(audit.OpVerify, displayName, br.Manifest); err != nil {
				return err
			}

			if br.Signature == nil {
				auditLog(audit.OpVerify, inFile, "", "", "", false, "bundle is not signed")
				printer.Error(util.ErrVerifyFailed, "bundle is not signed (no signature.sig)")
				os.Exit(util.ExitVerifyFailed)
				return nil
			}

			// Determine signing algorithm: prefer manifest field, then load key to detect.
			signAlgo := ""
			if br.Manifest.SignatureAlgo != nil && *br.Manifest.SignatureAlgo != "" {
				signAlgo = *br.Manifest.SignatureAlgo
			}
			if signAlgo == "" {
				_, keyAlgo, err := crypto.LoadAnyPublicKey(pubKey)
				if err != nil {
					return fmt.Errorf("load public key: %w", err)
				}
				signAlgo = keyAlgo
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

			var valid bool
			if plugin.GlobalRegistry().SignAlgo(signAlgo) != "" {
				valid, err = plugin.GlobalRegistry().Verify(signAlgo, pubKey, sigMsg, br.Signature)
			} else {
				pub, _, err := crypto.LoadAnyPublicKey(pubKey)
				if err != nil {
					return fmt.Errorf("load public key: %w", err)
				}
				valid, err = crypto.VerifySignature(pub, signAlgo, sigMsg, br.Signature)
			}
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

			// M24: optional transparency-log verification.
			var trResults []map[string]any
			if checkTransparency {
				if len(br.Manifest.Transparency) == 0 {
					return fmt.Errorf("--check-transparency was requested but the manifest has no transparency entries")
				}
				for i, entry := range br.Manifest.Transparency {
					res, err := verifyTransparencyEntry(entry, sigMsg, br.Signature, rekorPubKeyFile)
					if err != nil {
						return fmt.Errorf("transparency entry[%d] (uuid=%s): %w", i, entry.UUID, err)
					}
					trResults = append(trResults, res)
				}
			}

			switch printer.Mode {
			case OutputJSON:
				result := map[string]any{
					"bundle":    displayName,
					"verified":  true,
					"algorithm": signAlgo,
				}
				if signedAt != "" {
					result["signed_at"] = signedAt
				}
				if trResults != nil {
					result["transparency"] = trResults
				}
				return printer.JSON(result)
			default:
				printer.Human("Verified: %s", displayName)
				printer.Human("Algo:     %s", signAlgo)
				if signedAt != "" {
					printer.Human("Signed:   %s", signedAt)
				}
				printer.Human("Signature is valid.")
				for _, r := range trResults {
					printer.Human("Rekor:    log=%v index=%v uuid=%v OK", r["log_url"], r["log_index"], r["uuid"])
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input .vpack bundle to verify (required)")
	cmd.Flags().StringVar(&pubKey, "pubkey", "", "path to public key (required)")
	cmd.Flags().BoolVar(&checkTransparency, "check-transparency", false, "verify Sigstore Rekor inclusion proofs in the manifest")
	cmd.Flags().StringVar(&rekorPubKeyFile, "rekor-pubkey", "", "PEM-encoded Rekor public key (defaults to live fetch from each entry's log_url)")

	return cmd
}

// verifyTransparencyEntry validates one TransparencyEntry against the bundle's
// signature material. It cross-checks the data hash baked into the Rekor
// record against a SHA-256 of the supplied sigMsg (the canonical signing
// bytes), validates the signature inside the Rekor body matches the bundle's
// stored signature, and verifies Rekor's SET signature using either the
// supplied PEM (offline) or a live fetch from the log's /publicKey endpoint.
func verifyTransparencyEntry(entry bundle.TransparencyEntry, sigMsg, bundleSig []byte, rekorPubKeyFile string) (map[string]any, error) {
	if entry.EntryB64 == "" {
		return nil, fmt.Errorf("entry has no body — cannot verify")
	}
	var rec transparency.HashedRekordEntry
	if err := transparency.DecodeBody(entry.EntryB64, &rec); err != nil {
		return nil, fmt.Errorf("decode rekor body: %w", err)
	}

	// The Rekor record hashes the *exact* bytes that were signed. We computed
	// the same bytes above (sigMsg) and the bundle stores a copy of the
	// signature; both must match.
	wantHash := sha256.Sum256(sigMsg)
	if rec.Spec.Data.Hash.Algorithm != "sha256" {
		return nil, fmt.Errorf("unsupported rekor hash algorithm %q", rec.Spec.Data.Hash.Algorithm)
	}
	if rec.Spec.Data.Hash.Value != hex.EncodeToString(wantHash[:]) {
		return nil, fmt.Errorf("rekor data hash does not match bundle's signing message")
	}
	// Cross-check stored signature: the Rekor body holds base64(sig); compare
	// against the bundle's signature.sig (raw bytes).
	wantSigB64 := util.B64Encode(bundleSig)
	if rec.Spec.Signature.Content != wantSigB64 {
		return nil, fmt.Errorf("rekor signature content does not match bundle's signature.sig")
	}

	// SET verification.
	var pubPEM []byte
	if rekorPubKeyFile != "" {
		var err error
		pubPEM, err = os.ReadFile(rekorPubKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read --rekor-pubkey: %w", err)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		client := transparency.NewRekorClient(entry.LogURL)
		p, err := client.PublicKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch rekor pubkey from %s: %w", entry.LogURL, err)
		}
		pubPEM = p
	}
	if err := transparency.VerifySET(transparency.VerifyParams{
		RekorPubPEM:    pubPEM,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
		IntegratedTime: entry.IntegratedTime,
		Body:           entry.EntryB64,
		SETB64:         entry.SETB64,
	}); err != nil {
		return nil, err
	}

	return map[string]any{
		"log_url":         entry.LogURL,
		"log_index":       entry.LogIndex,
		"uuid":            entry.UUID,
		"integrated_time": entry.IntegratedTime,
	}, nil
}
