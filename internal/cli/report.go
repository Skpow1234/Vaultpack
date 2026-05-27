package cli

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/spf13/cobra"
)

type reportSummary struct {
	GeneratedAt      string         `json:"generated_at"`
	AuditLog         string         `json:"audit_log"`
	Entries          int            `json:"entries"`
	Successes        int            `json:"successes"`
	Failures         int            `json:"failures"`
	ByOperation      map[string]int `json:"by_operation"`
	ByOCSFClass      map[string]int `json:"by_ocsf_class"`
	FirstTimestamp   string         `json:"first_timestamp,omitempty"`
	LastTimestamp    string         `json:"last_timestamp,omitempty"`
	HashChainOK      bool           `json:"hash_chain_ok"`
	HashChainReason  string         `json:"hash_chain_reason,omitempty"`
	HashChainLastHex string         `json:"hash_chain_last_hex,omitempty"`
}

func newReportCmd() *cobra.Command {
	var (
		auditLogPath string
		format       string
		outPath      string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate compliance reports from the audit log",
		Long:  "Generate CSV or JSON compliance summaries from a VaultPack audit JSONL log, including operation counts, OCSF-style classes, success/failure totals, and audit hash-chain status.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if auditLogPath == "" {
				auditLogPath = flagAuditLog
			}
			if auditLogPath == "" {
				return fmt.Errorf("--audit-log is required (or set global --audit-log / VPACK_AUDIT_LOG)")
			}
			summary, rows, err := buildReport(auditLogPath)
			if err != nil {
				return err
			}

			var out *os.File
			if outPath == "" || outPath == "-" {
				out = os.Stdout
			} else {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("create report output: %w", err)
				}
				defer f.Close()
				out = f
			}

			switch format {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"summary": summary, "entries": rows})
			case "csv":
				w := csv.NewWriter(out)
				defer w.Flush()
				if err := w.Write([]string{"timestamp", "operation", "ocsf_class", "success", "input_file", "output_file", "bundle_hash", "key_fingerprint", "error", "entry_hash", "prev_hash"}); err != nil {
					return err
				}
				for _, e := range rows {
					if err := w.Write([]string{
						e.Timestamp,
						e.Operation,
						e.OCSFClass,
						fmt.Sprintf("%t", e.Success),
						e.InputFile,
						e.OutputFile,
						e.BundleHash,
						e.KeyFingerprint,
						e.Error,
						e.EntryHash,
						e.PrevHash,
					}); err != nil {
						return err
					}
				}
				return w.Error()
			default:
				return fmt.Errorf("--format must be json or csv")
			}
		},
	}
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Audit JSONL file to summarize (defaults to global --audit-log)")
	cmd.Flags().StringVar(&format, "format", "json", "Report format: json or csv")
	cmd.Flags().StringVar(&outPath, "out", "-", "Output path (default stdout)")
	return cmd
}

func buildReport(path string) (*reportSummary, []audit.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	sum := &reportSummary{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		AuditLog:    path,
		ByOperation: make(map[string]int),
		ByOCSFClass: make(map[string]int),
	}
	var rows []audit.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, nil, fmt.Errorf("parse audit log: %w", err)
		}
		if e.OCSFClass == "" {
			e.OCSFClass = audit.OCSFClass(e.Operation)
		}
		rows = append(rows, e)
		sum.Entries++
		if e.Success {
			sum.Successes++
		} else {
			sum.Failures++
		}
		sum.ByOperation[e.Operation]++
		sum.ByOCSFClass[e.OCSFClass]++
		if sum.FirstTimestamp == "" || e.Timestamp < sum.FirstTimestamp {
			sum.FirstTimestamp = e.Timestamp
		}
		if e.Timestamp > sum.LastTimestamp {
			sum.LastTimestamp = e.Timestamp
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("read audit log: %w", err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Timestamp < rows[j].Timestamp })
	vr, err := audit.VerifyFile(path)
	if err != nil {
		return nil, nil, err
	}
	sum.HashChainOK = vr.OK
	sum.HashChainReason = vr.Reason
	sum.HashChainLastHex = vr.LastHash
	return sum, rows, nil
}
