package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Global flag values shared across all commands.
var (
	flagJSON    bool
	flagQuiet   bool
	flagVerbose bool
)

// NewRootCmd creates the top-level cobra command with global flags.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "vaultpack",
		Short:   "Protect data artifacts with encryption, hashing, and signing",
		Long:    "VaultPack encrypts, hashes, and signs data artifacts into portable .vpack bundles.",
		Version: Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Configure zerolog level based on --verbose / --quiet.
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			if flagVerbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
			if flagQuiet {
				zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			}
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags available to every subcommand.
	pf := root.PersistentFlags()
	pf.BoolVar(&flagJSON, "json", false, "output results as JSON")
	pf.BoolVar(&flagQuiet, "quiet", false, "minimal output (errors only)")
	pf.BoolVar(&flagVerbose, "verbose", false, "enable debug logging")

	// Register subcommands.
	root.AddCommand(newHashCmd())
	root.AddCommand(newProtectCmd())
	root.AddCommand(newDecryptCmd())
	root.AddCommand(newInspectCmd())
	root.AddCommand(newKeygenCmd())
	root.AddCommand(newSignCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newVerifyIntegrityCmd())
	root.AddCommand(newSplitKeyCmd())
	root.AddCommand(newCombineKeyCmd())
	root.AddCommand(newMenuCmd())

	return root
}

// Execute runs the root command and exits with the correct code.
func Execute() {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
