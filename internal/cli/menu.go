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
				huh.NewOption("Verify integrity (decrypt + hash check)", "verify-integrity"),
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
		case "verify-integrity":
			return runVerifyIntegrityMenu()
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
		inFile       string
		outFile      string
		keyOutFile   string
		aad          string
		hashAlg      string
		cipherAlg    string
		compressAlg  string
		wantSign     bool
		signingPriv  string
		keyMode      string
		password     string
		kdfAlg       string
		recipientPub string
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
			huh.NewSelect[string]().
				Title("Key mode").
				Description("Choose how to encrypt").
				Options(
					huh.NewOption("Generate key file (default)", "keyfile"),
					huh.NewOption("Password-based encryption", "password"),
					huh.NewOption("Recipient public key (hybrid)", "recipient"),
				).
				Value(&keyMode),
		),
	).Run()
	if err != nil {
		return err
	}

	switch keyMode {
	case "keyfile":
		err = huh.NewInput().
			Title("Key output path (leave blank for default)").
			Placeholder("<input>.key").
			Value(&keyOutFile).
			Run()
		if err != nil {
			return err
		}
	case "password":
		err = huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Password").
					Placeholder("Enter a strong passphrase").
					EchoMode(huh.EchoModePassword).
					Value(&password),
				huh.NewSelect[string]().
					Title("Key derivation function").
					Options(
						huh.NewOption("Argon2id (recommended)", "argon2id"),
						huh.NewOption("scrypt", "scrypt"),
						huh.NewOption("PBKDF2-SHA256 (FIPS)", "pbkdf2-sha256"),
					).
					Value(&kdfAlg),
			),
		).Run()
		if err != nil {
			return err
		}
	case "recipient":
		err = huh.NewInput().
			Title("Recipient's public key (PEM)").
			Placeholder("/path/to/recipient.pub").
			Description("Scheme is auto-detected: X25519, ECIES-P256, RSA-OAEP").
			Value(&recipientPub).
			Run()
		if err != nil {
			return err
		}
	}

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Encryption cipher").
				Options(
					huh.NewOption("AES-256-GCM (default)", "aes-256-gcm"),
					huh.NewOption("ChaCha20-Poly1305", "chacha20-poly1305"),
					huh.NewOption("XChaCha20-Poly1305 (24-byte nonce)", "xchacha20-poly1305"),
				).
				Value(&cipherAlg),
			huh.NewSelect[string]().
				Title("Hash algorithm for plaintext").
				Options(
					huh.NewOption("SHA-256 (default)", "sha256"),
					huh.NewOption("SHA-512", "sha512"),
					huh.NewOption("SHA3-256", "sha3-256"),
					huh.NewOption("SHA3-512", "sha3-512"),
					huh.NewOption("BLAKE2b-256", "blake2b-256"),
					huh.NewOption("BLAKE2b-512", "blake2b-512"),
					huh.NewOption("BLAKE3", "blake3"),
				).
				Value(&hashAlg),
			huh.NewSelect[string]().
				Title("Pre-encryption compression").
				Description("Compress data before encrypting (saves space for large files)").
				Options(
					huh.NewOption("None (default)", "none"),
					huh.NewOption("gzip", "gzip"),
					huh.NewOption("zstd (fast, good ratio)", "zstd"),
				).
				Value(&compressAlg),
			huh.NewInput().
				Title("Additional authenticated data (optional)").
				Placeholder("env=prod,app=payments").
				Value(&aad),
			huh.NewConfirm().
				Title("Sign the bundle?").
				Value(&wantSign),
		),
	).Run()
	if err != nil {
		return err
	}

	if wantSign {
		err = huh.NewInput().
			Title("Path to private signing key").
			Placeholder("signing.key").
			Value(&signingPriv).
			Run()
		if err != nil {
			return err
		}
	}

	// Build args.
	args := []string{"protect", "--in", inFile, "--hash-algo", hashAlg, "--cipher", cipherAlg}
	if outFile != "" {
		args = append(args, "--out", outFile)
	}
	if compressAlg != "" && compressAlg != "none" {
		args = append(args, "--compress", compressAlg)
	}
	switch keyMode {
	case "keyfile":
		if keyOutFile != "" {
			args = append(args, "--key-out", keyOutFile)
		}
	case "password":
		args = append(args, "--password", password, "--kdf", kdfAlg)
	case "recipient":
		args = append(args, "--recipient", recipientPub)
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
		inFile     string
		outFile    string
		keyMode    string
		keyFile    string
		password   string
		privKeyFile string
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
			huh.NewSelect[string]().
				Title("Decryption method").
				Options(
					huh.NewOption("Key file", "keyfile"),
					huh.NewOption("Password", "password"),
					huh.NewOption("Private key (hybrid)", "privkey"),
				).
				Value(&keyMode),
		),
	).Run()
	if err != nil {
		return err
	}

	switch keyMode {
	case "keyfile":
		err = huh.NewInput().
			Title("Path to decryption key").
			Placeholder("file.key").
			Value(&keyFile).
			Run()
	case "password":
		err = huh.NewInput().
			Title("Password").
			EchoMode(huh.EchoModePassword).
			Value(&password).
			Run()
	case "privkey":
		err = huh.NewInput().
			Title("Path to private key (PEM)").
			Placeholder("recipient.key").
			Value(&privKeyFile).
			Run()
	}
	if err != nil {
		return err
	}

	args := []string{"decrypt", "--in", inFile, "--out", outFile}
	switch keyMode {
	case "keyfile":
		args = append(args, "--key", keyFile)
	case "password":
		args = append(args, "--password", password)
	case "privkey":
		args = append(args, "--privkey", privKeyFile)
	}

	root := NewRootCmd()
	root.SetArgs(args)
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
	var (
		inFile  string
		hashAlg string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input file to hash").
				Placeholder("/path/to/file").
				Value(&inFile),
			huh.NewSelect[string]().
				Title("Hash algorithm").
				Options(
					huh.NewOption("SHA-256 (default)", "sha256"),
					huh.NewOption("SHA-512", "sha512"),
					huh.NewOption("SHA3-256", "sha3-256"),
					huh.NewOption("SHA3-512", "sha3-512"),
					huh.NewOption("BLAKE2b-256", "blake2b-256"),
					huh.NewOption("BLAKE2b-512", "blake2b-512"),
					huh.NewOption("BLAKE3", "blake3"),
				).
				Value(&hashAlg),
		),
	).Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"hash", "--in", inFile, "--algo", hashAlg})
	return root.Execute()
}

func runKeygenMenu() error {
	var (
		outPrefix string
		signAlg   string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Output prefix for key pair").
				Placeholder("signing").
				Description("Produces <prefix>.key (private) and <prefix>.pub (public)").
				Value(&outPrefix),
			huh.NewSelect[string]().
				Title("Algorithm").
				Options(
					huh.NewOption("Ed25519 — signing (default)", "ed25519"),
					huh.NewOption("ECDSA P-256 — signing", "ecdsa-p256"),
					huh.NewOption("ECDSA P-384 — signing", "ecdsa-p384"),
					huh.NewOption("RSA-PSS 2048 — signing", "rsa-pss-2048"),
					huh.NewOption("RSA-PSS 4096 — signing", "rsa-pss-4096"),
					huh.NewOption("X25519 — hybrid encryption", "x25519-aes-256-gcm"),
					huh.NewOption("ECIES P-256 — hybrid encryption", "ecies-p256"),
					huh.NewOption("RSA-OAEP 2048 — hybrid encryption", "rsa-oaep-2048"),
					huh.NewOption("RSA-OAEP 4096 — hybrid encryption", "rsa-oaep-4096"),
				).
				Value(&signAlg),
		),
	).Run()
	if err != nil {
		return err
	}

	root := NewRootCmd()
	root.SetArgs([]string{"keygen", "--out", outPrefix, "--algo", signAlg})
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
				Title("Path to private signing key").
				Placeholder("signing.key").
				Description("Algorithm is auto-detected from the key format").
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
				Title("Path to public key").
				Placeholder("signing.pub").
				Description("Algorithm is auto-detected from key and manifest").
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

func runVerifyIntegrityMenu() error {
	var (
		inFile  string
		keyMode string
		keyFile string
		password string
		privKeyFile string
	)

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Input .vpack bundle").
				Placeholder("/path/to/bundle.vpack").
				Value(&inFile),
			huh.NewSelect[string]().
				Title("Decryption method").
				Options(
					huh.NewOption("Key file", "keyfile"),
					huh.NewOption("Password", "password"),
					huh.NewOption("Private key (hybrid)", "privkey"),
				).
				Value(&keyMode),
		),
	).Run()
	if err != nil {
		return err
	}

	switch keyMode {
	case "keyfile":
		err = huh.NewInput().
			Title("Path to decryption key").
			Placeholder("file.key").
			Value(&keyFile).
			Run()
	case "password":
		err = huh.NewInput().
			Title("Password").
			EchoMode(huh.EchoModePassword).
			Value(&password).
			Run()
	case "privkey":
		err = huh.NewInput().
			Title("Path to private key (PEM)").
			Placeholder("recipient.key").
			Value(&privKeyFile).
			Run()
	}
	if err != nil {
		return err
	}

	args := []string{"verify-integrity", "--in", inFile}
	switch keyMode {
	case "keyfile":
		args = append(args, "--key", keyFile)
	case "password":
		args = append(args, "--password", password)
	case "privkey":
		args = append(args, "--privkey", privKeyFile)
	}

	root := NewRootCmd()
	root.SetArgs(args)
	return root.Execute()
}

func init() {
	// Ensure huh respects NO_COLOR and TERM=dumb.
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		// huh handles this automatically via lipgloss/colorprofile.
		return
	}
}
