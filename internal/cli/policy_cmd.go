package cli

import (
	"fmt"
	"os"
	"os/user"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/policy"
	"github.com/spf13/cobra"
)

// newPolicyCmd builds the `vaultpack policy` command tree with three sub-verbs:
//
//	policy validate --file path/policy.yaml
//	policy test     --file path/policy.yaml --bundle x.vpack --op decrypt [--user alice]
//	policy show
//
// `validate` parses+lints a policy file. `test` dry-runs a decision against a
// real bundle without actually running the requested operation. `show` reports
// the policy path currently in effect.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect, validate, and test VaultPack policies",
		Long:  "Manage the RBAC policy that gates VaultPack operations (decrypt, sign, verify, rotation, etc).",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyTestCmd())
	cmd.AddCommand(newPolicyShowCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse and validate a policy file (YAML, JSON, or Rego)",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			ev, err := policy.Load(file)
			if err != nil {
				return err
			}
			out := map[string]any{
				"file":  file,
				"valid": true,
			}
			if p, ok := ev.(*policy.Policy); ok {
				out["rule_count"] = len(p.Rules)
				if p.Default == "" {
					out["default"] = "allow"
				} else {
					out["default"] = string(p.Default)
				}
			} else {
				out["engine"] = "rego"
			}
			if printer.Mode == OutputJSON {
				return printer.JSON(out)
			}
			printer.Human("Policy:   %s", file)
			printer.Human("Status:   valid")
			if p, ok := ev.(*policy.Policy); ok {
				def := p.Default
				if def == "" {
					def = "allow"
				}
				printer.Human("Default:  %s", def)
				printer.Human("Rules:    %d", len(p.Rules))
			} else {
				printer.Human("Engine:   rego (OPA)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "policy file path (required)")
	return cmd
}

func newPolicyTestCmd() *cobra.Command {
	var (
		file       string
		bundlePath string
		op         string
		usr        string
		hostname   string
	)
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Dry-run a policy decision against a bundle / operation pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			if op == "" {
				return fmt.Errorf("--op is required (e.g. decrypt)")
			}
			ev, err := policy.Load(file)
			if err != nil {
				return err
			}
			var m *bundle.Manifest
			if bundlePath != "" {
				localIn, cleanup, err := resolveBundlePath(bundlePath)
				if err != nil {
					return err
				}
				if cleanup != nil {
					defer cleanup()
				}
				m, _, err = bundle.ReadManifestOnly(localIn)
				if err != nil {
					return fmt.Errorf("read bundle: %w", err)
				}
			}
			if usr == "" {
				if u, err := user.Current(); err == nil {
					usr = u.Username
				}
			}
			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			dec, err := ev.Evaluate(policy.Context{
				Operation:  op,
				BundlePath: bundlePath,
				Manifest:   m,
				User:       usr,
				Hostname:   hostname,
			})
			if err != nil {
				return err
			}
			out := map[string]any{
				"policy":    file,
				"operation": op,
				"user":      usr,
				"hostname":  hostname,
				"bundle":    bundlePath,
				"action":    string(dec.Action),
				"rule":      dec.MatchedRule,
				"reason":    dec.Reason,
				"allowed":   dec.Allowed(),
			}
			if printer.Mode == OutputJSON {
				return printer.JSON(out)
			}
			printer.Human("Policy:    %s", file)
			printer.Human("Operation: %s", op)
			printer.Human("User:      %s", usr)
			printer.Human("Bundle:    %s", bundlePath)
			printer.Human("Decision:  %s", dec.Action)
			if dec.MatchedRule != "" {
				printer.Human("Rule:      %s", dec.MatchedRule)
			}
			if dec.Reason != "" {
				printer.Human("Reason:    %s", dec.Reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "policy file path (required)")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "bundle to evaluate against (optional)")
	cmd.Flags().StringVar(&op, "op", "", "operation name (e.g. decrypt, verify, sign) (required)")
	cmd.Flags().StringVar(&usr, "user", "", "principal username (defaults to current user)")
	cmd.Flags().StringVar(&hostname, "host", "", "hostname (defaults to current host)")
	return cmd
}

func newPolicyShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Report the policy that would be applied to this CLI invocation",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)
			path := flagPolicy
			source := "--policy"
			if path == "" {
				path = os.Getenv("VAULTPACK_POLICY")
				if path != "" {
					source = "VAULTPACK_POLICY"
				}
			}
			if path == "" {
				// config.Get() is loaded by PersistentPreRun.
				if ev := policy.Global(); ev == nil {
					if printer.Mode == OutputJSON {
						return printer.JSON(map[string]any{"policy": nil, "enforced": false})
					}
					printer.Human("Policy:   (none)")
					printer.Human("Enforced: no")
					return nil
				}
			}
			ev := policy.Global()
			out := map[string]any{
				"policy":   path,
				"source":   source,
				"enforced": ev != nil,
			}
			if p, ok := ev.(*policy.Policy); ok {
				out["rule_count"] = len(p.Rules)
				def := p.Default
				if def == "" {
					def = "allow"
				}
				out["default"] = string(def)
			}
			if printer.Mode == OutputJSON {
				return printer.JSON(out)
			}
			printer.Human("Policy:   %s", path)
			printer.Human("Source:   %s", source)
			printer.Human("Enforced: yes")
			if p, ok := ev.(*policy.Policy); ok {
				def := p.Default
				if def == "" {
					def = "allow"
				}
				printer.Human("Default:  %s", def)
				printer.Human("Rules:    %d", len(p.Rules))
			}
			return nil
		},
	}
	return cmd
}
