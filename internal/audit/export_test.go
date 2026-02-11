package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExportFilter_Matches(t *testing.T) {
	e := &Entry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Operation:    OpProtect,
		KeyFingerprint: "sha256:abc",
	}
	var f ExportFilter
	if !f.Matches(e) {
		t.Error("nil filter should match")
	}
	f.Operation = OpDecrypt
	if f.Matches(e) {
		t.Error("wrong operation should not match")
	}
	f.Operation = OpProtect
	if !f.Matches(e) {
		t.Error("same operation should match")
	}
	f.KeyFingerprint = "abc"
	if !f.Matches(e) {
		t.Error("substring key fingerprint should match")
	}
	f.KeyFingerprint = "xyz"
	if f.Matches(e) {
		t.Error("non-substring key fingerprint should not match")
	}
}

func TestReadAuditLog_ExportCSV_ExportJSON(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	entries := []string{
		`{"timestamp":"2026-01-01T00:00:00Z","operation":"protect","input_file":"a","output_file":"b","success":true}`,
		`{"timestamp":"2026-01-01T00:00:01Z","operation":"decrypt","input_file":"b","output_file":"a","success":true}`,
	}
	if err := os.WriteFile(logPath, []byte(entries[0]+"\n"+entries[1]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	read, err := ReadAuditLog(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(read))
	}
	csvOut, err := ExportCSV(read)
	if err != nil {
		t.Fatal(err)
	}
	if len(csvOut) < 50 {
		t.Error("CSV output too short")
	}
	jsonOut, err := ExportJSON(read, "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(jsonOut) < 50 {
		t.Error("JSON output too short")
	}
}
