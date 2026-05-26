package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	yaml "gopkg.in/yaml.v3"
)

// Evaluator is implemented by both the native Policy and the OPA/Rego wrapper.
// Holding only this interface in the global lets us swap in alternative
// implementations without invasive plumbing.
type Evaluator interface {
	Evaluate(ctx Context) (Decision, error)
}

// Load reads a policy file from disk. The format is determined by the file
// extension: ".yaml" / ".yml" / ".json" are parsed by the native engine; ".rego"
// loads via OPA. Returns an error for unknown extensions.
func Load(path string) (Evaluator, error) {
	if path == "" {
		return nil, fmt.Errorf("policy path is empty")
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml", ".json", ".rego":
		// supported below
	default:
		return nil, fmt.Errorf("unsupported policy file extension %q (want .yaml/.yml/.json/.rego)", ext)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	switch ext {
	case ".yaml", ".yml":
		return loadYAML(data)
	case ".json":
		return loadJSON(data)
	case ".rego":
		return loadRego(path, data)
	}
	return nil, fmt.Errorf("unreachable")
}

func loadYAML(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse yaml policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func loadJSON(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse json policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// --- Global ---

var (
	globalMu  sync.RWMutex
	globalEvaluator Evaluator
)

// SetGlobal installs the process-wide policy used by the CLI. Passing nil
// disables enforcement entirely.
func SetGlobal(e Evaluator) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalEvaluator = e
}

// Global returns the process-wide policy, or nil if none has been configured.
func Global() Evaluator {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalEvaluator
}

// Enforce evaluates the global policy (if any) against ctx and returns the
// decision. When no policy is set, the operation is implicitly allowed.
// Callers should refuse the requested operation if Decision.Allowed() is false.
func Enforce(ctx Context) (Decision, error) {
	e := Global()
	if e == nil {
		return Decision{Action: ActionAllow, Reason: "no policy"}, nil
	}
	return e.Evaluate(ctx)
}
