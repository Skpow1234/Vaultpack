package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileLogger_Log(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &Entry{
		Operation: OpProtect,
		InputFile: "test.txt",
		OutputFile: "test.vpack",
		Success:   true,
	}
	if err := logger.Log(e); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(e); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("expected 2 lines, got %d", lines)
	}
}

func TestNopLogger_Log(t *testing.T) {
	var n NopLogger
	if err := n.Log(&Entry{Operation: OpDecrypt}); err != nil {
		t.Fatal(err)
	}
}
