package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/Skpow1234/Vaultpack/internal/config"
	"github.com/Skpow1234/Vaultpack/internal/plugin"
	"github.com/Skpow1234/Vaultpack/internal/policy"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Global flag values shared across all commands.
var (
	flagJSON    bool
	flagQuiet   bool
	flagVerbose bool
	flagAuditLog string
	flagConfig  string
	flagProfile string
	flagPolicy  string
	// effectiveAuditLogPath is set in PersistentPreRun from precedence: CLI > env > config.
	effectiveAuditLogPath string
)

// NewRootCmd creates the top-level cobra command with global flags.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "vaultpack",
		Short:   "Protect data artifacts with encryption, hashing, and signing",
		Long:    "VaultPack encrypts, hashes, and signs data artifacts into portable .vpack bundles.",
		Version: Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Load config (optional): --config or VPACK_CONFIG, then ~/.vpack.yaml, ./.vpack.yaml.
			// Profile: --profile or VPACK_PROFILE. Errors are ignored so commands run with defaults.
			_, _ = config.Load(flagConfig, flagProfile)
			// Precedence: CLI flags > env vars > config file > built-in defaults.
			root := cmd.Root()
			if root != nil && root.PersistentFlags().Changed("audit-log") {
				effectiveAuditLogPath = flagAuditLog
			} else if v := os.Getenv("VAULTPACK_AUDIT_LOG"); v != "" {
				effectiveAuditLogPath = v
			} else if c := config.Get(); c != nil && c.AuditLog != "" {
				effectiveAuditLogPath = c.AuditLog
			} else {
				effectiveAuditLogPath = ""
			}

			// Configure zerolog level based on --verbose / --quiet.
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			if flagVerbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
			if flagQuiet {
				zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			}

			// Policy resolution: --policy > VAULTPACK_POLICY env > config.policy_file.
			policyPath := flagPolicy
			if policyPath == "" {
				policyPath = os.Getenv("VAULTPACK_POLICY")
			}
			if policyPath == "" {
				if c := config.Get(); c != nil {
					policyPath = c.PolicyFile
				}
			}
			if policyPath != "" {
				ev, err := policy.Load(policyPath)
				if err != nil {
					// Surface but don't crash the entire CLI; "fail-closed" would block
					// emergency use. The error is logged so operators see it.
					l := zerolog.New(os.Stderr)
					l.Error().Err(err).Str("policy", policyPath).Msg("policy load failed; enforcement disabled")
				} else {
					policy.SetGlobal(ev)
				}
			}
			// Plugin discovery: VPACK_PLUGIN_DIR or config plugin_dir.
			pluginDir := os.Getenv(config.EnvPluginDir)
			if pluginDir == "" && config.Get() != nil {
				pluginDir = config.Get().PluginDir
			}
			plugin.DiscoverFromDir(pluginDir)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags available to every subcommand.
	pf := root.PersistentFlags()
	pf.BoolVar(&flagJSON, "json", false, "output results as JSON")
	pf.BoolVar(&flagQuiet, "quiet", false, "minimal output (errors only)")
	pf.BoolVar(&flagVerbose, "verbose", false, "enable debug logging")

	// Azure Blob Storage flags.
	pf.StringVar(&azureAccountName, "azure-account", "", "Azure storage account name (or AZURE_STORAGE_ACCOUNT env)")
	pf.StringVar(&azureConnectionString, "azure-connection-string", "", "Azure storage connection string (or AZURE_STORAGE_CONNECTION_STRING env)")

	// AWS S3 flags (also resolved from AWS_REGION/AWS_PROFILE env vars and the SDK default credential chain).
	pf.StringVar(&awsRegion, "aws-region", "", "AWS region for s3:// URIs (or AWS_REGION env)")
	pf.StringVar(&awsProfile, "aws-profile", "", "AWS shared config profile (or AWS_PROFILE env)")
	pf.StringVar(&awsS3Endpoint, "s3-endpoint", "", "Override S3 endpoint URL (MinIO, LocalStack)")
	pf.BoolVar(&awsS3PathStyle, "s3-path-style", false, "Use path-style S3 addressing")

	// Audit trail.
	pf.StringVar(&flagAuditLog, "audit-log", "", "Append-only audit log file (or VAULTPACK_AUDIT_LOG env)")

	// Configuration (Milestone 16).
	pf.StringVar(&flagConfig, "config", "", "Config file path (or VPACK_CONFIG env); default: ~/.vpack.yaml, ./.vpack.yaml")
	pf.StringVar(&flagProfile, "profile", "", "Config profile: dev, staging, prod (or VPACK_PROFILE env)")

	// Policy (M23).
	pf.StringVar(&flagPolicy, "policy", "", "Policy file (YAML/JSON/Rego) to enforce before operations (or VAULTPACK_POLICY env)")

	// Register subcommands.
	root.AddCommand(newHashCmd())
	root.AddCommand(newProtectCmd())
	root.AddCommand(newDecryptCmd())
	root.AddCommand(newInspectCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newKeygenCmd())
	root.AddCommand(newSignCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newVerifyIntegrityCmd())
	root.AddCommand(newSplitKeyCmd())
	root.AddCommand(newCombineKeyCmd())
	root.AddCommand(newBatchProtectCmd())
	root.AddCommand(newBatchDecryptCmd())
	root.AddCommand(newBatchInspectCmd())
	root.AddCommand(newAttestCmd())
	root.AddCommand(newSealCmd())
	root.AddCommand(newVerifySealCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newMenuCmd())
	root.AddCommand(newConfigCmd())
	// M22: rotation & rewrap.
	root.AddCommand(newRewrapCmd())
	root.AddCommand(newRotateKeyCmd())
	root.AddCommand(newAddRecipientCmd())
	root.AddCommand(newRemoveRecipientCmd())
	// M23: policy.
	root.AddCommand(newPolicyCmd())
	// M26: service mode.
	root.AddCommand(newServeCmd())

	return root
}

// Execute runs the root command and exits with the correct code.
func Execute() {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
