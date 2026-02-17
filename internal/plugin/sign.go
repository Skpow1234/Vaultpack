package plugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
)

// KeygenSign runs the plugin keygen for a sign algorithm: plugin keygen --type sign --algo <name> --out <prefix>.
// The plugin must write <prefix>.key and <prefix>.pub (and may add VPACK-SIGN-ALGO to the key file).
func (r *Registry) KeygenSign(algo, outPrefix string) error {
	path := r.SignAlgo(algo)
	if path == "" {
		return fmt.Errorf("plugin: no plugin for sign algorithm %q", algo)
	}
	cmd := exec.Command(path, "keygen", "--type", "sign", "--algo", algo, "--out", outPrefix)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("plugin keygen sign: %w", err)
	}
	return nil
}

// Sign runs the plugin sign: plugin sign --algo <name> --privkey <path>. Stdin = message; stdout = signature base64.
func (r *Registry) Sign(algo, privKeyPath string, message []byte) ([]byte, error) {
	path := r.SignAlgo(algo)
	if path == "" {
		return nil, fmt.Errorf("plugin: no plugin for sign algorithm %q", algo)
	}
	cmd := exec.Command(path, "sign", "--algo", algo, "--privkey", privKeyPath)
	cmd.Stdin = io.NopCloser(bytes.NewReader(message))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("plugin sign: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(string(bytesTrim(out)))
	if err != nil {
		return nil, fmt.Errorf("plugin sign output: %w", err)
	}
	return sig, nil
}

// Verify runs the plugin verify: plugin verify --algo <name> --pubkey <path> --signature <base64>. Stdin = message; exit 0 = valid.
func (r *Registry) Verify(algo, pubKeyPath string, message, signature []byte) (bool, error) {
	path := r.SignAlgo(algo)
	if path == "" {
		return false, fmt.Errorf("plugin: no plugin for sign algorithm %q", algo)
	}
	cmd := exec.Command(path, "verify", "--algo", algo, "--pubkey", pubKeyPath, "--signature", base64.StdEncoding.EncodeToString(signature))
	cmd.Stdin = io.NopCloser(bytes.NewReader(message))
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
			return false, nil
		}
		return false, fmt.Errorf("plugin verify: %w", err)
	}
	return true, nil
}
