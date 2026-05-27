// Package audit provides tamper-evident, append-only logging of VaultPack operations.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	OpRewrap          = "rewrap"
	OpRotateKey       = "rotate-key"
	OpAddRecipient    = "add-recipient"
	OpRemoveRecipient = "remove-recipient"
	OpPolicyDeny      = "policy-deny"
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
	PrevHash     string `json:"prev_hash,omitempty"`
	EntryHash    string `json:"entry_hash,omitempty"`
	OCSFClass    string `json:"ocsf_class,omitempty"`
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

	f.mu.Lock()
	defer f.mu.Unlock()

	prev, err := lastHash(f.path)
	if err != nil {
		return err
	}
	e.PrevHash = prev
	e.OCSFClass = OCSFClass(e.Operation)
	e.EntryHash, err = computeEntryHash(e)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit marshal: %w", err)
	}
	line := append(raw, '\n')

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

// VerifyResult summarizes a tamper-evident audit-chain verification.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Entries  int    `json:"entries"`
	BadLine  int    `json:"bad_line,omitempty"`
	Reason   string `json:"reason,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
}

// VerifyFile verifies the hash chain in an audit JSONL file. Legacy entries
// without entry_hash are tolerated, but once a chained entry appears each
// subsequent chained entry must link to the previous chained hash.
func VerifyFile(path string) (*VerifyResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit verify open: %w", err)
	}
	defer file.Close()

	res := &VerifyResult{OK: true}
	prev := ""
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("audit verify parse line %d: %w", line, err)
		}
		res.Entries++
		if e.EntryHash == "" {
			continue
		}
		if e.PrevHash != prev {
			return &VerifyResult{OK: false, Entries: res.Entries, BadLine: line, Reason: "prev_hash mismatch", LastHash: prev}, nil
		}
		want, err := computeEntryHash(&e)
		if err != nil {
			return nil, err
		}
		if e.EntryHash != want {
			return &VerifyResult{OK: false, Entries: res.Entries, BadLine: line, Reason: "entry_hash mismatch", LastHash: prev}, nil
		}
		prev = e.EntryHash
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit verify read: %w", err)
	}
	res.LastHash = prev
	return res, nil
}

// OCSFClass maps VaultPack operations to a compact OCSF-style category label.
func OCSFClass(op string) string {
	switch op {
	case OpProtect, OpDecrypt, OpRewrap, OpRotateKey, OpAddRecipient, OpRemoveRecipient:
		return "encryption_activity"
	case OpSign, OpVerify, OpVerifyIntegrity, OpAttest:
		return "integrity_activity"
	case OpPolicyDeny:
		return "authorization_activity"
	case OpKeygen, OpSplitKey, OpCombineKey:
		return "key_management"
	default:
		return "application_activity"
	}
}

func lastHash(path string) (string, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("audit last hash open: %w", err)
	}
	defer file.Close()
	var last string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err == nil && e.EntryHash != "" {
			last = e.EntryHash
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return "", fmt.Errorf("audit last hash read: %w", err)
	}
	return last, nil
}

func computeEntryHash(e *Entry) (string, error) {
	c := *e
	c.EntryHash = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("audit hash marshal: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// NopLogger discards all entries. Use when audit logging is disabled.
type NopLogger struct{}

func (NopLogger) Log(*Entry) error { return nil }
