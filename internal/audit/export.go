package audit

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ExportFilter filters audit entries for export.
type ExportFilter struct {
	Since     *time.Time // include only entries on or after
	Until     *time.Time // include only entries before
	Operation string     // exact operation name, or "" for all
	KeyFingerprint string // entries with this key fingerprint (substring match), or ""
}

// Matches returns true if e should be included.
func (f *ExportFilter) Matches(e *Entry) bool {
	if f == nil {
		return true
	}
	if f.Operation != "" && e.Operation != f.Operation {
		return false
	}
	if f.KeyFingerprint != "" && !strings.Contains(e.KeyFingerprint, f.KeyFingerprint) {
		return false
	}
	if f.Since != nil {
		t, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil || t.Before(*f.Since) {
			return false
		}
	}
	if f.Until != nil {
		t, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil || !t.Before(*f.Until) {
			return false
		}
	}
	return true
}

// ReadAuditLog reads a JSON-lines audit log file and returns entries (optionally filtered).
func ReadAuditLog(path string, filter *ExportFilter) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // skip malformed lines
		}
		if filter != nil && !filter.Matches(&e) {
			continue
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ExportJSON writes entries as a JSON array to w.
func ExportJSON(entries []Entry, indent string) ([]byte, error) {
	if indent != "" {
		return json.MarshalIndent(entries, "", indent)
	}
	return json.Marshal(entries)
}

// ExportCSV writes entries as CSV to w. Header row included.
func ExportCSV(entries []Entry) ([]byte, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)
	header := []string{"timestamp", "operation", "input_file", "output_file", "bundle_hash", "key_fingerprint", "user", "hostname", "success", "error"}
	if err := w.Write(header); err != nil {
		return nil, err
	}
	for _, e := range entries {
		row := []string{
			e.Timestamp,
			e.Operation,
			e.InputFile,
			e.OutputFile,
			e.BundleHash,
			e.KeyFingerprint,
			e.User,
			e.Hostname,
			fmt.Sprint(e.Success),
			e.Error,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
