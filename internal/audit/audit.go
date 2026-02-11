// Package audit provides tamper-evident, append-only logging of VaultPack operations.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"os/user"
)

// Operation names for audit entries.
const (
	OpProtect         = "protect"
	OpDecrypt         = "decrypt"
	OpInspect         = "inspect"
	OpHash            = "hash"
	OpKeygen          = "keygen"
	OpSign            = "sign"
	OpVerify          = "verify"
	OpVerifyIntegrity = "verify-integrity"
	OpSplitKey        = "split-key"
	OpCombineKey      = "combine-key"
	OpBatchProtect    = "batch-protect"
	OpBatchDecrypt    = "batch-decrypt"
	OpBatchInspect   = "batch-inspect"
	OpAttest          = "attest"
	OpSeal            = "seal"
	OpVerifySeal      = "verify-seal"
)

// Entry is one JSON-lines record written to the audit log.
type Entry struct {
	Timestamp    string `json:"timestamp"`     // RFC3339
	Operation    string `json:"operation"`
	InputFile    string `json:"input_file,omitempty"`
	OutputFile   string `json:"output_file,omitempty"`
	BundleHash   string `json:"bundle_hash,omitempty"`   // SHA-256 of bundle or payload (hex/base64)
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	User         string `json:"user,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// Logger writes audit entries. Safe for concurrent use.
type Logger interface {
	Log(e *Entry) error
}

// FileLogger appends JSON-lines to a file. Implements Logger.
type FileLogger struct {
	path string
	mu   sync.Mutex
}

// NewFileLogger creates a logger that appends to path. Parent dirs are created if needed.
func NewFileLogger(path string) (*FileLogger, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit log dir: %w", err)
		}
	}
	return &FileLogger{path: path}, nil
}

// Log appends one JSON line to the audit log file.
func (f *FileLogger) Log(e *Entry) error {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Hostname == "" {
		e.Hostname, _ = os.Hostname()
	}
	if e.User == "" {
		if u, err := user.Current(); err == nil {
			e.User = u.Username
		}
	}

	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit marshal: %w", err)
	}
	line := append(raw, '\n')

	f.mu.Lock()
	defer f.mu.Unlock()

	file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("audit log open: %w", err)
	}
	_, err = file.Write(line)
	file.Close()
	if err != nil {
		return fmt.Errorf("audit log write: %w", err)
	}
	return nil
}

// NopLogger discards all entries. Use when audit logging is disabled.
type NopLogger struct{}

func (NopLogger) Log(*Entry) error { return nil }
