package repo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// rewriteRows atomically replaces a JSONL file with the supplied rows.
// Used by Anchor; not exported because external callers should append
// (via Repo.Add) and never rewrite history.
func rewriteRows[T any](dir, name string, rows []T) error {
	dst := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("rewrite %s: temp: %w", name, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	for _, r := range rows {
		data, err := json.Marshal(r)
		if err != nil {
			tmp.Close()
			return fmt.Errorf("rewrite %s: marshal: %w", name, err)
		}
		if _, err := tmp.Write(append(data, '\n')); err != nil {
			tmp.Close()
			return fmt.Errorf("rewrite %s: write: %w", name, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("rewrite %s: sync: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("rewrite %s: close: %w", name, err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("rewrite %s: rename: %w", name, err)
	}
	return nil
}
