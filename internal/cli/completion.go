package cli

import "github.com/spf13/cobra"

func newCompletionCmd(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generate shell completion scripts",
		Long:  "Generate shell completion scripts for bash, zsh, fish, or PowerShell.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "bash",
		Short: "Generate bash completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(cmd.OutOrStdout())
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "zsh",
		Short: "Generate zsh completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenZshCompletion(cmd.OutOrStdout())
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "fish",
		Short: "Generate fish completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "powershell",
		Aliases: []string{"ps1"},
		Short:   "Generate PowerShell completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenPowerShellCompletion(cmd.OutOrStdout())
		},
	})
	return cmd
}
