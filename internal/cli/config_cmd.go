package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/config"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show effective configuration and precedence",
		Long: "Show the effective configuration used by vaultpack (from config file and profile).\n\n" +
			"Precedence (highest wins):\n" +
			"  1. CLI flags (e.g. --audit-log, --cipher)\n" +
			"  2. Environment variables (e.g. VAULTPACK_AUDIT_LOG)\n" +
			"  3. Config file (from --config, VPACK_CONFIG, or ~/.vpack.yaml / ./.vpack.yaml)\n" +
			"  4. Profile overrides (from --profile or VPACK_PROFILE: dev, staging, prod)\n" +
			"  5. Built-in defaults\n\n" +
			"Config file keys: audit_log, cipher, chunk_size, output_dir, default_key_path, default_pubkey_path, recipients.\n" +
			"Profiles can override any of these under the 'profiles' key (e.g. profiles.prod.audit_log).",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)
			cfg := config.Get()
			if cfg == nil {
				cfg = &config.EffectiveConfig{}
				*cfg = config.DefaultEffective()
			}

			switch printer.Mode {
			case OutputJSON:
				out, err := json.MarshalIndent(cfg, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout, string(out))
			default:
				printer.Human("Effective configuration:")
				printer.Human("  audit_log:         %q", cfg.AuditLog)
				printer.Human("  cipher:            %s", cfg.Cipher)
				printer.Human("  chunk_size:        %d", cfg.ChunkSize)
				printer.Human("  output_dir:        %q", cfg.OutputDir)
				printer.Human("  default_key_path:  %q", cfg.DefaultKeyPath)
				printer.Human("  default_pubkey_path: %q", cfg.DefaultPubPath)
				if len(cfg.Recipients) > 0 {
					printer.Human("  recipients:        %v", cfg.Recipients)
				}
			}
			return nil
		},
	}
	return cmd
}
