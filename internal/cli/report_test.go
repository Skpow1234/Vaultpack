package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/audit"
)

func TestBuildReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Log(&audit.Entry{Operation: audit.OpProtect, InputFile: "a", Success: true})
	_ = l.Log(&audit.Entry{Operation: audit.OpDecrypt, InputFile: "b", Success: false, Error: "denied"})

	sum, rows, err := buildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Entries != 2 || sum.Successes != 1 || sum.Failures != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if !sum.HashChainOK {
		t.Fatalf("expected hash chain ok: %+v", sum)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	if sum.ByOperation[audit.OpProtect] != 1 || sum.ByOCSFClass["encryption_activity"] != 2 {
		t.Fatalf("unexpected counts: %+v", sum)
	}
}

func TestReportCommandJSONAndCSV(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	l, _ := audit.NewFileLogger(logPath)
	_ = l.Log(&audit.Entry{Operation: audit.OpProtect, InputFile: "a", Success: true})

	jsonOut := filepath.Join(dir, "report.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"report", "--audit-log", logPath, "--format", "json", "--out", jsonOut})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("report json: %v", err)
	}
	raw, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("bad json: %v", err)
	}

	csvOut := filepath.Join(dir, "report.csv")
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{"report", "--audit-log", logPath, "--format", "csv", "--out", csvOut})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("report csv: %v", err)
	}
	csvRaw, _ := os.ReadFile(csvOut)
	if !bytes.Contains(csvRaw, []byte("timestamp,operation,ocsf_class")) || !strings.Contains(string(csvRaw), "protect") {
		t.Fatalf("unexpected csv: %s", csvRaw)
	}
}
