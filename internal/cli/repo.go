package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/repo"
	"github.com/spf13/cobra"
)

func newRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Tamper-evident append-only repository of .vpack bundles (M27)",
		Long: `Manage an append-only Merkle log of .vpack bundles. Each "repo add"
appends a new leaf to an RFC 6962-style history tree, signs the resulting
root with the repo's signing key, and (optionally) anchors the root in
Sigstore Rekor.

A repo is just a directory:

  myrepo/
    repo.json        # config: schema, signing key fingerprint, ...
    entries.jsonl    # append-only: one entry per added bundle
    roots.jsonl      # append-only: one signed root per add
    bundles/         # optional: copies of every added .vpack

"repo verify" walks the entire log forward and recomputes every root,
proving the chain has not been tampered with.`,
	}
	cmd.AddCommand(newRepoInitCmd())
	cmd.AddCommand(newRepoAddCmd())
	cmd.AddCommand(newRepoListCmd())
	cmd.AddCommand(newRepoVerifyCmd())
	cmd.AddCommand(newRepoAnchorCmd())
	return cmd
}

func newRepoInitCmd() *cobra.Command {
	var (
		dir          string
		description  string
		signingKey   string
		rekorURL     string
		storeBundles bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new repo directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				return fmt.Errorf("--dir is required")
			}
			var keyPEM []byte
			if signingKey != "" {
				b, err := os.ReadFile(signingKey)
				if err != nil {
					return fmt.Errorf("read --signing-key: %w", err)
				}
				keyPEM = b
			}
			if err := repo.Init(dir, repo.InitOptions{
				Description:   description,
				SigningKeyPEM: keyPEM,
				RekorURL:      rekorURL,
				StoreBundles:  storeBundles,
			}); err != nil {
				return err
			}
			printer := NewPrinter(flagJSON, flagQuiet)
			printer.Human("repo initialized at %s%s", dir, signedMsg(keyPEM != nil))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Repo directory (will be created if missing)")
	cmd.Flags().StringVar(&description, "description", "", "Human-readable description (stored in repo.json)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM private key used to sign every new root (recommended)")
	cmd.Flags().StringVar(&rekorURL, "rekor-url", "", "Default Sigstore Rekor URL used by 'repo anchor'")
	cmd.Flags().BoolVar(&storeBundles, "store-bundles", false, "Keep a copy of every added .vpack in bundles/")
	return cmd
}

func newRepoAddCmd() *cobra.Command {
	var (
		dir           string
		bundlePath    string
		bundleName    string
		signingKey    string
		embedManifest bool
		copyBundle    bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Append a .vpack bundle to the repo",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" || bundlePath == "" {
				return fmt.Errorf("--dir and --bundle are required")
			}
			bundleBytes, err := os.ReadFile(bundlePath)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}
			var keyPEM []byte
			if signingKey != "" {
				b, err := os.ReadFile(signingKey)
				if err != nil {
					return fmt.Errorf("read --signing-key: %w", err)
				}
				keyPEM = b
			}
			r, err := repo.Open(dir, keyPEM)
			if err != nil {
				return err
			}
			name := bundleName
			if name == "" {
				name = baseName(bundlePath)
			}
			res, err := r.Add(repo.AddOptions{
				BundleBytes:   bundleBytes,
				BundleName:    name,
				EmbedManifest: embedManifest,
				CopyBundle:    copyBundle,
				SigningKeyPEM: keyPEM,
			})
			if err != nil {
				return err
			}
			printer := NewPrinter(flagJSON, flagQuiet)
			if flagJSON {
				return printer.JSON(map[string]any{
					"entry": res.Entry,
					"root":  res.Root,
				})
			}
			printer.Human("added seq=%d sha256=%s tree_size=%d root=%s",
				res.Entry.Seq, res.Entry.BundleSHA256, res.Root.TreeSize, res.Root.RootHashHex)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Repo directory")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the .vpack file to add")
	cmd.Flags().StringVar(&bundleName, "name", "", "Friendly name to record (defaults to basename)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM private key (overrides repo default, must match fingerprint)")
	cmd.Flags().BoolVar(&embedManifest, "embed-manifest", false, "Embed the bundle's manifest (base64) in the entry")
	cmd.Flags().BoolVar(&copyBundle, "copy", false, "Also write the .vpack into bundles/<sha>.vpack (requires --store-bundles at init)")
	return cmd
}

func newRepoListCmd() *cobra.Command {
	var (
		dir   string
		limit int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List entries in the repo",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				return fmt.Errorf("--dir is required")
			}
			r, err := repo.Open(dir, nil)
			if err != nil {
				return err
			}
			entries, roots, err := r.List(limit)
			if err != nil {
				return err
			}
			printer := NewPrinter(flagJSON, flagQuiet)
			if flagJSON {
				return printer.JSON(map[string]any{
					"entries": entries,
					"roots":   roots,
				})
			}
			for i, e := range entries {
				printer.Human("%4d  %s  %s  root=%s",
					e.Seq, e.Timestamp, e.BundleSHA256[:16], roots[i].RootHashHex[:16])
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Repo directory")
	cmd.Flags().IntVar(&limit, "limit", 0, "Show only the last N entries (0 = all)")
	return cmd
}

func newRepoVerifyCmd() *cobra.Command {
	var (
		dir       string
		verifyKey string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Recompute the entire chain and verify every root signature",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				return fmt.Errorf("--dir is required")
			}
			r, err := repo.Open(dir, nil)
			if err != nil {
				return err
			}
			var keyPEM []byte
			if verifyKey != "" {
				b, err := os.ReadFile(verifyKey)
				if err != nil {
					return fmt.Errorf("read --verify-key: %w", err)
				}
				keyPEM = b
			}
			res, err := r.Verify(keyPEM)
			if err != nil {
				return err
			}
			printer := NewPrinter(flagJSON, flagQuiet)
			if flagJSON {
				out, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(out))
			} else if res.OK {
				printer.Human("OK  entries=%d  final_root=%s", res.NumEntries, res.FinalRootHex)
			} else {
				printer.Human("FAIL  bad_entry=%d  reason=%s", res.BadEntryIndex, res.Reason)
			}
			if !res.OK {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Repo directory")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "PEM public key used to verify root signatures (required if repo is signed)")
	return cmd
}

func newRepoAnchorCmd() *cobra.Command {
	var (
		dir        string
		signingKey string
		rekorURL   string
		seq        int64
	)
	cmd := &cobra.Command{
		Use:   "anchor",
		Short: "Upload a signed root to Sigstore Rekor for public timestamping",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" || signingKey == "" {
				return fmt.Errorf("--dir and --signing-key are required")
			}
			keyPEM, err := os.ReadFile(signingKey)
			if err != nil {
				return fmt.Errorf("read --signing-key: %w", err)
			}
			r, err := repo.Open(dir, keyPEM)
			if err != nil {
				return err
			}
			root, err := r.Anchor(repo.AnchorOptions{
				RekorURL:      rekorURL,
				SigningKeyPEM: keyPEM,
				Seq:           seq,
			})
			if err != nil {
				return err
			}
			printer := NewPrinter(flagJSON, flagQuiet)
			if flagJSON {
				return printer.JSON(root)
			}
			printer.Human("anchored seq=%d  uuid=%s  log_index=%d",
				root.Seq, root.RekorUUID, root.RekorLogIndex)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Repo directory")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM private key (must match repo's signing key)")
	cmd.Flags().StringVar(&rekorURL, "rekor-url", "", "Rekor URL (overrides repo default)")
	cmd.Flags().Int64Var(&seq, "seq", -1, "Sequence number to anchor (-1 = latest)")
	return cmd
}

func signedMsg(signed bool) string {
	if signed {
		return " (signed)"
	}
	return " (unsigned — pass --signing-key to enable root signatures)"
}

func baseName(path string) string {
	// Avoid pulling in filepath here; the CLI uses forward and back slashes.
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	if path == "" {
		return "bundle.vpack"
	}
	return strings.TrimSpace(path)
}
