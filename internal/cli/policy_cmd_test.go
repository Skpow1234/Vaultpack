package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/policy"
)

// writeYAMLPolicy writes the given source to a tempdir/<name>.yaml file and returns the path.
func writeYAMLPolicy(t *testing.T, name, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPolicyValidateCmd_OK exercises `vaultpack policy validate --file ...` happy path.
func TestPolicyValidateCmd_OK(t *testing.T) {
	p := writeYAMLPolicy(t, "p.yaml", `
version: 1
default: allow
rules:
  - name: r1
    action: deny
    when:
      operation: [decrypt]
      user: bob
`)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"policy", "validate", "--file", p})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestPolicyValidateCmd_BadFile ensures a malformed policy is rejected with a clear error.
func TestPolicyValidateCmd_BadFile(t *testing.T) {
	p := writeYAMLPolicy(t, "p.yaml", `
version: 1
rules:
  - action: not-a-real-action
`)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"policy", "validate", "--file", p})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

// TestPolicyTestCmd_NoBundleNoManifestPredicates ensures `policy test` works
// without a bundle for principal/operation-only rules.
func TestPolicyTestCmd_NoBundleNoManifestPredicates(t *testing.T) {
	p := writeYAMLPolicy(t, "p.yaml", `
version: 1
default: deny
rules:
  - name: allow-alice
    action: allow
    when:
      operation: [decrypt]
      user: alice
`)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"policy", "test", "--file", p, "--op", "decrypt", "--user", "alice"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("policy test: %v", err)
	}
}

// TestEnforceFromFlag_DenyDecrypt is a full end-to-end check: protect a file,
// install a deny-decrypt policy via --policy, and confirm decrypt returns
// ErrPolicyDenied.
func TestEnforceFromFlag_DenyDecrypt(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	out := filepath.Join(dir, "secret.dec")
	if err := os.WriteFile(in, []byte("policy-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "k.key")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	policyFile := writeYAMLPolicy(t, "deny.yaml", `
version: 1
default: allow
rules:
  - name: no-decrypts
    action: deny
    reason: "decrypts disabled for tests"
    when:
      operation: [decrypt]
`)

	// Reset any global policy from earlier tests, then run decrypt under --policy.
	t.Cleanup(func() { policy.SetGlobal(nil) })

	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"--policy", policyFile,
		"decrypt", "--in", bundleFile, "--out", out, "--key", keyFile,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected decrypt to be denied by policy")
	}
	if !strings.Contains(err.Error(), "policy denied") {
		t.Errorf("expected 'policy denied' error, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("output file should not exist after policy denial")
	}
}

// TestEnforceFromFlag_AllowDecrypt is the matching positive test: with an allow
// policy, the same protect + decrypt round-trip succeeds.
func TestEnforceFromFlag_AllowDecrypt(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	out := filepath.Join(dir, "secret.dec")
	if err := os.WriteFile(in, []byte("policy-allow"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "k.key")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	policyFile := writeYAMLPolicy(t, "allow.yaml", `
version: 1
default: allow
`)
	t.Cleanup(func() { policy.SetGlobal(nil) })

	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"--policy", policyFile,
		"decrypt", "--in", bundleFile, "--out", out, "--key", keyFile,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("decrypt under allow policy: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(got) != "policy-allow" {
		t.Errorf("plaintext mismatch: %q", got)
	}
}
