package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLoggerHashChainAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(&Entry{Operation: OpProtect, InputFile: "a", Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(&Entry{Operation: OpDecrypt, InputFile: "b", Success: false, Error: "nope"}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 2 || res.LastHash == "" {
		t.Fatalf("unexpected verify result: %+v", res)
	}
}

func TestVerifyFileDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := NewFileLogger(path)
	_ = l.Log(&Entry{Operation: OpProtect, InputFile: "a", Success: true})
	_ = l.Log(&Entry{Operation: OpDecrypt, InputFile: "b", Success: true})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"success":true`, `"success":false`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected tampered chain to fail")
	}
}

func TestOCSFClass(t *testing.T) {
	if got := OCSFClass(OpPolicyDeny); got != "authorization_activity" {
		t.Fatalf("OCSFClass(policy-deny) = %q", got)
	}
}
