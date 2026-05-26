package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/spf13/cobra"
)

// diffEntry is one field-level difference between two manifests.
type diffEntry struct {
	Field string `json:"field"`
	A     string `json:"a"`
	B     string `json:"b"`
}

func newDiffCmd() *cobra.Command {
	var (
		fileA       string
		fileB       string
		ignoreTime  bool
		ignoreNonce bool
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two .vpack bundles' manifests",
		Long: "Compare two .vpack bundles by inspecting their manifests and plaintext hashes.\n\n" +
			"Reports per-field differences (plaintext hash, AEAD, key ID, scheme, recipients, signature, etc.).\n" +
			"Exit codes: 0 = identical, 10 = differences found.\n\n" +
			"Azure: use az://container/blob.vpack for either input.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if fileA == "" || fileB == "" {
				return fmt.Errorf("--a and --b are required")
			}

			// Resolve Azure URIs.
			pathA, cleanupA, err := resolveBundlePath(fileA)
			if err != nil {
				return fmt.Errorf("read %s: %w", fileA, err)
			}
			if cleanupA != nil {
				defer cleanupA()
			}
			pathB, cleanupB, err := resolveBundlePath(fileB)
			if err != nil {
				return fmt.Errorf("read %s: %w", fileB, err)
			}
			if cleanupB != nil {
				defer cleanupB()
			}

			mA, _, err := bundle.ReadManifestOnly(pathA)
			if err != nil {
				return fmt.Errorf("read manifest %s: %w", fileA, err)
			}
			mB, _, err := bundle.ReadManifestOnly(pathB)
			if err != nil {
				return fmt.Errorf("read manifest %s: %w", fileB, err)
			}

			diffs := diffManifests(mA, mB, ignoreTime, ignoreNonce)
			plaintextEqual := mA.Plaintext.Algo == mB.Plaintext.Algo &&
				mA.Plaintext.DigestB64 == mB.Plaintext.DigestB64

			switch printer.Mode {
			case OutputJSON:
				_ = printer.JSON(map[string]any{
					"a":               fileA,
					"b":               fileB,
					"identical":       len(diffs) == 0,
					"plaintext_equal": plaintextEqual,
					"differences":     diffs,
				})
			default:
				printer.Human("A: %s", fileA)
				printer.Human("B: %s", fileB)
				if plaintextEqual {
					printer.Human("Plaintext: identical (%s:%s)", mA.Plaintext.Algo, short(mA.Plaintext.DigestB64))
				} else {
					printer.Human("Plaintext: DIFFERENT (A=%s:%s, B=%s:%s)",
						mA.Plaintext.Algo, short(mA.Plaintext.DigestB64),
						mB.Plaintext.Algo, short(mB.Plaintext.DigestB64))
				}
				if len(diffs) == 0 {
					printer.Human("Bundles are identical (manifest fields match).")
				} else {
					printer.Human("")
					printer.Human("Differences (%d):", len(diffs))
					for _, d := range diffs {
						printer.Human("  %s", d.Field)
						printer.Human("    A: %s", d.A)
						printer.Human("    B: %s", d.B)
					}
				}
			}

			if len(diffs) > 0 {
				os.Exit(10)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&fileA, "a", "", "first bundle path (required)")
	cmd.Flags().StringVar(&fileB, "b", "", "second bundle path (required)")
	cmd.Flags().BoolVar(&ignoreTime, "ignore-time", false, "ignore created_at and signed_at timestamps")
	cmd.Flags().BoolVar(&ignoreNonce, "ignore-nonce", false, "ignore nonce, tag, ephemeral key, and wrapped DEK values (which differ per encryption)")
	return cmd
}

// resolveBundlePath turns an Azure URI into a local temp file path and returns a cleanup func.
// For local paths it returns the original path and a nil cleanup.
func resolveBundlePath(in string) (string, func(), error) {
	if isAzure(in) {
		tmp, err := azureDownload(in)
		if err != nil {
			return "", nil, err
		}
		return tmp, func() { os.Remove(tmp) }, nil
	}
	return in, nil, nil
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// diffManifests returns a sorted list of differing fields between a and b.
func diffManifests(a, b *bundle.Manifest, ignoreTime, ignoreNonce bool) []diffEntry {
	var out []diffEntry
	add := func(field, av, bv string) {
		if av != bv {
			out = append(out, diffEntry{Field: field, A: av, B: bv})
		}
	}

	add("version", a.Version, b.Version)
	if !ignoreTime {
		add("created_at", a.CreatedAt, b.CreatedAt)
	}
	add("input.name", a.Input.Name, b.Input.Name)
	add("input.size", fmt.Sprintf("%d", a.Input.Size), fmt.Sprintf("%d", b.Input.Size))
	add("plaintext_hash.algo", a.Plaintext.Algo, b.Plaintext.Algo)
	add("plaintext_hash.digest_b64", a.Plaintext.DigestB64, b.Plaintext.DigestB64)
	add("encryption.aead", a.Encryption.AEAD, b.Encryption.AEAD)
	if !ignoreNonce {
		add("encryption.nonce_b64", a.Encryption.NonceB64, b.Encryption.NonceB64)
		add("encryption.tag_b64", a.Encryption.TagB64, b.Encryption.TagB64)
	}
	add("encryption.key_id.algo", a.Encryption.KeyID.Algo, b.Encryption.KeyID.Algo)
	add("encryption.key_id.digest_b64", a.Encryption.KeyID.DigestB64, b.Encryption.KeyID.DigestB64)
	add("encryption.aad_b64", strOrEmpty(a.Encryption.AADB64), strOrEmpty(b.Encryption.AADB64))
	add("encryption.chunk_size", intPtr(a.Encryption.ChunkSize), intPtr(b.Encryption.ChunkSize))
	add("encryption.kms_key_id", a.Encryption.KmsKeyID, b.Encryption.KmsKeyID)
	if !ignoreNonce {
		add("encryption.kms_wrapped_dek_b64", a.Encryption.KmsWrappedDEKB64, b.Encryption.KmsWrappedDEKB64)
	}

	// KDF
	add("encryption.kdf", kdfSummary(a.Encryption.KDF), kdfSummary(b.Encryption.KDF))

	// Hybrid
	if !ignoreNonce {
		add("encryption.hybrid", hybridSummary(a.Encryption.Hybrid), hybridSummary(b.Encryption.Hybrid))
	} else {
		add("encryption.hybrid.scheme", hybridScheme(a.Encryption.Hybrid), hybridScheme(b.Encryption.Hybrid))
		add("encryption.hybrid.recipients", hybridRecipients(a.Encryption.Hybrid), hybridRecipients(b.Encryption.Hybrid))
	}

	// Compression
	add("compression.algo", compAlgo(a.Compress), compAlgo(b.Compress))
	add("compression.original_size", compSize(a.Compress), compSize(b.Compress))

	// Key splitting
	add("key_splitting", splitSummary(a.KeySplitting), splitSummary(b.KeySplitting))

	// Signature
	add("signature_algo", strOrEmpty(a.SignatureAlgo), strOrEmpty(b.SignatureAlgo))
	if !ignoreTime {
		add("signed_at", strOrEmpty(a.SignedAt), strOrEmpty(b.SignedAt))
	}

	// Ciphertext size
	add("ciphertext.size", fmt.Sprintf("%d", a.Ciphertext.Size), fmt.Sprintf("%d", b.Ciphertext.Size))

	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func strOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func intPtr(p *int) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}

func kdfSummary(k *bundle.KDFMeta) string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("algo=%s time=%d memory=%d threads=%d n=%d r=%d p=%d iter=%d",
		k.Algo, k.Time, k.Memory, k.Threads, k.N, k.R, k.P, k.Iterations)
}

func hybridSummary(h *bundle.HybridMeta) string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("scheme=%s recipients=%d fingerprint=%s",
		h.Scheme, len(h.Recipients), h.RecipientFingerprintB64)
}

func hybridScheme(h *bundle.HybridMeta) string {
	if h == nil {
		return ""
	}
	return h.Scheme
}

func hybridRecipients(h *bundle.HybridMeta) string {
	if h == nil {
		return ""
	}
	fps := make([]string, 0, len(h.Recipients))
	for _, r := range h.Recipients {
		fps = append(fps, r.Scheme+":"+r.FingerprintB64)
	}
	sort.Strings(fps)
	if h.RecipientFingerprintB64 != "" {
		return h.RecipientFingerprintB64
	}
	return fmt.Sprintf("%v", fps)
}

func compAlgo(c *bundle.CompressionMeta) string {
	if c == nil {
		return ""
	}
	return c.Algo
}

func compSize(c *bundle.CompressionMeta) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%d", c.OriginalSize)
}

func splitSummary(s *bundle.KeySplitMeta) string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s %d-of-%d", s.Scheme, s.Threshold, s.Total)
}
