package cli

import (
	"bytes"
	"testing"
)

func TestDoctorJSON(t *testing.T) {
	checks := runDoctorChecks()
	if len(checks) == 0 {
		t.Fatal("expected at least one doctor check")
	}
	if !doctorOK(checks) {
		t.Fatalf("expected default doctor checks to pass: %+v", checks)
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
