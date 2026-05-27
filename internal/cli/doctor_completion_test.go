package cli

import (
	"bytes"
	"testing"
)

func TestDoctorJSON(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--json", "doctor"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"checks"`)) {
		t.Fatalf("doctor JSON missing checks: %s", out.String())
	}
}

func TestCompletionBash(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"completion", "bash"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion bash: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("vaultpack")) {
		t.Fatalf("completion output did not mention vaultpack")
	}
}
