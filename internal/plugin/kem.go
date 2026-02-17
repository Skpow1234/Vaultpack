package plugin

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// EncapsulateResult matches the JSON output of a plugin encapsulate command.
type EncapsulateResult struct {
	DEKB64          string `json:"dek_b64"`
	EphemeralB64    string `json:"ephemeral_b64"`
	WrappedDEKB64   string `json:"wrapped_dek_b64"`
	Scheme          string `json:"scheme"`
}

// Keygen runs the plugin keygen for a KEM scheme: plugin keygen --type kem --algo <name> --out <prefix>.
// The plugin must write <prefix>.key and <prefix>.pub and may add VPACK-KEM-SCHEME to the .pub file.
func (r *Registry) KeygenKEM(scheme, outPrefix string) error {
	path := r.KEMScheme(scheme)
	if path == "" {
		return fmt.Errorf("plugin: no plugin for KEM scheme %q", scheme)
	}
	privPath := outPrefix
	if filepath.Ext(privPath) != ".key" {
		privPath = outPrefix + ".key"
	}
	cmd := exec.Command(path, "keygen", "--type", "kem", "--algo", scheme, "--out", outPrefix)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("plugin keygen: %w", err)
	}
	return nil
}

// Encapsulate runs the plugin encapsulate: plugin encapsulate --algo <name> --pubkey <path>.
// Stdin can be empty (plugin generates DEK) or DEK hex for wrap. Returns result from stdout JSON.
func (r *Registry) Encapsulate(scheme, pubKeyPath string, dekForWrap []byte) (*EncapsulateResult, error) {
	path := r.KEMScheme(scheme)
	if path == "" {
		return nil, fmt.Errorf("plugin: no plugin for KEM scheme %q", scheme)
	}
	cmd := exec.Command(path, "encapsulate", "--algo", scheme, "--pubkey", pubKeyPath)
	if len(dekForWrap) > 0 {
		cmd.Env = append(os.Environ(), "VPACK_DEK_B64="+base64.StdEncoding.EncodeToString(dekForWrap))
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("plugin encapsulate: %w", err)
	}
	var res EncapsulateResult
	if err := json.Unmarshal(bytesTrim(out), &res); err != nil {
		return nil, fmt.Errorf("plugin encapsulate output: %w", err)
	}
	if res.Scheme == "" {
		res.Scheme = scheme
	}
	return &res, nil
}

// Decapsulate runs the plugin decapsulate: plugin decapsulate --algo <name> --privkey <path>.
// Ciphertext (ephemeral + wrapped DEK) is passed via env VPACK_CIPHERTEXT_B64 (JSON object base64) or stdin.
// Returns DEK from stdout (hex or base64 line).
func (r *Registry) Decapsulate(scheme, privKeyPath string, ephemeralB64, wrappedDEKB64 string) ([]byte, error) {
	path := r.KEMScheme(scheme)
	if path == "" {
		return nil, fmt.Errorf("plugin: no plugin for KEM scheme %q", scheme)
	}
	// Encode input as JSON then base64 for env
	input := map[string]string{}
	if ephemeralB64 != "" {
		input["ephemeral_b64"] = ephemeralB64
	}
	if wrappedDEKB64 != "" {
		input["wrapped_dek_b64"] = wrappedDEKB64
	}
	inputB64 := ""
	if len(input) > 0 {
		b, _ := json.Marshal(input)
		inputB64 = base64.StdEncoding.EncodeToString(b)
	}
	cmd := exec.Command(path, "decapsulate", "--algo", scheme, "--privkey", privKeyPath)
	cmd.Env = append(os.Environ(), "VPACK_CIPHERTEXT_B64="+inputB64)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("plugin decapsulate: %w", err)
	}
	line := strings.TrimSpace(string(bytesTrim(out)))
	// Try base64 first, then hex
	dek, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		dek, err = hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("plugin decapsulate: invalid DEK output: %w", err)
		}
	}
	return dek, nil
}
