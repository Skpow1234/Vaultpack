package cli

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

func newMenuCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "menu",
		Short: "Interactive mode — guided workflow",
		Long:  "Launch an interactive menu to walk through VaultPack operations step by step.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var action string

			err := huh.NewSelect[string]().
				Title("What would you like to do?").
				Options(
					huh.NewOption("Protect a file (encrypt + bundle)", "protect"),
					huh.NewOption("Decrypt a .vpack bundle", "decrypt"),
					huh.NewOption("Inspect a .vpack bundle", "inspect"),
					huh.NewOption("Hash a file", "hash"),
					huh.NewOption("Generate signing key pair", "keygen"),
					huh.NewOption("Sign a .vpack bundle", "sign"),
					huh.NewOption("Verify a .vpack bundle", "verify"),
					huh.NewOption("Exit", "exit"),
				).
				Value(&action).
				Run()
			if err != nil {
				return err
			}

			switch action {
			case "protect":
				return runProtectMenu(cmd)
			case "decrypt":
				return runDecryptMenu(cmd)
			case "inspect":
				return runInspectMenu()
			case "hash":
				return runHashMenu()
			case "keygen":
				return runKeygenMenu()
			case "sign":
				return runSignMenu()
			case "verify":
				return runVerifyMenu()
			case "exit":
				fmt.Println("Goodbye.")
				return nil
			}
			return nil
		},
	}
	return cmd
}

func runProtectMenu(cmd *cobra.Command) error {
	var (
		inFile      string
		outFile     string
		keyOutFile  string
		aad         string
		wantSign    bool
		signingPriv string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input file to protect").
				Placeholder("/path/to/file").
				Value(&inFile),
			huh.NewInput().
				Title("Output bundle path (leave blank for default)").
				Placeholder("<input>.vpack").
				Value(&outFile),
			huh.NewInput().
				Title("Key output path (leave blank for default)").
				Placeholder("<input>.key").
				Value(&keyOutFile),
			huh.NewInput().
				Title("Additional authenticated data (optional)").
				Placeholder("env=prod,app=payments").
				Value(&aad),
			huh.NewConfirm().
				Title("Sign the bundle with Ed25519?").
				Value(&wantSign),
		),
	).Run()
	if err != nil {
		return err
	}

	if wantSign {
		err = huh.NewInput().
			Title("Path to Ed25519 private key").
			Placeholder("signing.key").
			Value(&signingPriv).
			Run()
		if err != nil {
			return err
		}
	}

	// Build args.
	args := []string{"protect", "--in", inFile}
	if outFile != "" {
		args = append(args, "--out", outFile)
	}
	if keyOutFile != "" {
		args = append(args, "--key-out", keyOutFile)
	}
	if aad != "" {
		args = append(args, "--aad", aad)
	}
	if wantSign {
		args = append(args, "--sign", "--signing-priv", signingPriv)
	}

	root := NewRootCmd()
	root.SetArgs(args)
	return root.Execute()
}

func runDecryptMenu(cmd *cobra.Command) error {
	var (
		inFile  string
		outFile string
		keyFile string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input .vpack bundle").
				Placeholder("/path/to/bundle.vpack").
				Value(&inFile),
			huh.NewInput().
				Title("Output plaintext path").
				Placeholder("/path/to/output").
				Value(&outFile),
			huh.NewInput().
				Title("Path to decryption key").
				Placeholder("file.key").
				Value(&keyFile),
		),
	).Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"decrypt", "--in", inFile, "--out", outFile, "--key", keyFile})
	return root.Execute()
}

func runInspectMenu() error {
	var (
		inFile  string
		useJSON bool
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input .vpack bundle").
				Placeholder("/path/to/bundle.vpack").
				Value(&inFile),
			huh.NewConfirm().
				Title("Output as JSON?").
				Value(&useJSON),
		),
	).Run()
	if err != nil {
		return err
	}

	args := []string{"inspect", "--in", inFile}
	if useJSON {
		args = append(args, "--json")
	}

	root := NewRootCmd()
	root.SetArgs(args)
	return root.Execute()
}

func runHashMenu() error {
	var inFile string

	err := huh.NewInput().
		Title("Input file to hash").
		Placeholder("/path/to/file").
		Value(&inFile).
		Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"hash", "--in", inFile})
	return root.Execute()
}

func runKeygenMenu() error {
	var outPrefix string

	err := huh.NewInput().
		Title("Output prefix for key pair").
		Placeholder("signing").
		Description("Produces <prefix>.key (private) and <prefix>.pub (public)").
		Value(&outPrefix).
		Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", outPrefix})
	return root.Execute()
}

func runSignMenu() error {
	var (
		inFile      string
		signingPriv string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input .vpack bundle to sign").
				Placeholder("/path/to/bundle.vpack").
				Value(&inFile),
			huh.NewInput().
				Title("Path to Ed25519 private key").
				Placeholder("signing.key").
				Value(&signingPriv),
		),
	).Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"sign", "--in", inFile, "--signing-priv", signingPriv})
	return root.Execute()
}

func runVerifyMenu() error {
	var (
		inFile string
		pubKey string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input .vpack bundle to verify").
				Placeholder("/path/to/bundle.vpack").
				Value(&inFile),
			huh.NewInput().
				Title("Path to Ed25519 public key").
				Placeholder("signing.pub").
				Value(&pubKey),
		),
	).Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "--in", inFile, "--pubkey", pubKey})
	return root.Execute()
}

func init() {
	// Ensure huh respects NO_COLOR and TERM=dumb.
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		// huh handles this automatically via lipgloss/colorprofile.
		return
	}
}
