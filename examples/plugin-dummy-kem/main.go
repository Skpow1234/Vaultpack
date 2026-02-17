// Dummy KEM plugin for VaultPack (Milestone 19 example).
// NOT SECURE — for demonstration only. Registers scheme "dummy-kem".
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const schemeName = "dummy-kem"

// Demo "wrapping": XOR with a constant byte. Do not use in production.
const wrapByte = 0x42

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--vpack-list" {
		out := map[string][]string{"kem": {schemeName}, "sign": {}}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return
	}

	if len(os.Args) < 3 {
		os.Exit(1)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "keygen":
		runKeygen(args)
	case "encapsulate":
		runEncapsulate(args)
	case "decapsulate":
		runDecapsulate(args)
	default:
		os.Exit(1)
	}
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	typ := fs.String("type", "", "")
	algo := fs.String("algo", "", "")
	out := fs.String("out", "", "")
	_ = fs.Parse(args)
	if *typ != "kem" || *algo != schemeName || *out == "" {
		os.Exit(1)
	}
	privPath := *out
	if filepath.Ext(privPath) != ".key" {
		privPath = *out + ".key"
	}
	pubPath := strings.TrimSuffix(privPath, ".key") + ".pub"
	// Dummy key material (fixed for demo).
	privContent := "dummy-kem-private-key\n"
	pubContent := "VPACK-KEM-SCHEME: " + schemeName + "\n" + "dummy-kem-public-key\n"
	if err := os.WriteFile(privPath, []byte(privContent), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(pubPath, []byte(pubContent), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runEncapsulate(args []string) {
	fs := flag.NewFlagSet("encapsulate", flag.ExitOnError)
	algo := fs.String("algo", "", "")
	pubkey := fs.String("pubkey", "", "")
	_ = fs.Parse(args)
	if *algo != schemeName || *pubkey == "" {
		os.Exit(1)
	}
	// Generate or use provided DEK.
	var dek []byte
	if b64 := os.Getenv("VPACK_DEK_B64"); b64 != "" {
		var err error
		dek, err = base64.StdEncoding.DecodeString(b64)
		if err != nil || len(dek) == 0 {
			os.Exit(1)
		}
	} else {
		dek = make([]byte, 32)
		for i := range dek {
			dek[i] = byte(i + 1)
		}
	}
	// "Wrap": XOR with constant (demo only).
	wrapped := make([]byte, len(dek))
	for i := range dek {
		wrapped[i] = dek[i] ^ wrapByte
	}
	res := map[string]string{
		"dek_b64":         base64.StdEncoding.EncodeToString(dek),
		"wrapped_dek_b64": base64.StdEncoding.EncodeToString(wrapped),
		"scheme":          schemeName,
	}
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}

func runDecapsulate(args []string) {
	fs := flag.NewFlagSet("decapsulate", flag.ExitOnError)
	algo := fs.String("algo", "", "")
	privkey := fs.String("privkey", "", "")
	_ = fs.Parse(args)
	if *algo != schemeName || *privkey == "" {
		os.Exit(1)
	}
	inputB64 := os.Getenv("VPACK_CIPHERTEXT_B64")
	if inputB64 == "" {
		os.Exit(1)
	}
	raw, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		os.Exit(1)
	}
	var input map[string]string
	if err := json.Unmarshal(raw, &input); err != nil {
		os.Exit(1)
	}
	wrappedB64, ok := input["wrapped_dek_b64"]
	if !ok || wrappedB64 == "" {
		os.Exit(1)
	}
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		os.Exit(1)
	}
	dek := make([]byte, len(wrapped))
	for i := range wrapped {
		dek[i] = wrapped[i] ^ wrapByte
	}
	fmt.Println(base64.StdEncoding.EncodeToString(dek))
}
