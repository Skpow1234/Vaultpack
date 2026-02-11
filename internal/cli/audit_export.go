package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit trail and export",
		Long:  "Parent command for audit log export. Use 'vaultpack audit export --format csv' to export the audit log.",
	}
	cmd.AddCommand(newAuditExportCmd())
	return cmd
}

func newAuditExportCmd() *cobra.Command {
	var (
		logPath   string
		format    string
		since     string
		until     string
		operation string
		keyFP     string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit log to CSV or JSON",
		Long:  "Read the audit log file and output filtered entries as CSV or JSON. Use --since and --until for date range (RFC3339 or 2006-01-02), --operation and --key-fingerprint to filter.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if logPath == "" {
				logPath = flagAuditLog
				if logPath == "" {
					logPath = os.Getenv("VAULTPACK_AUDIT_LOG")
				}
			}
			if logPath == "" {
				return fmt.Errorf("audit log path required: set --audit-log, --log, or VAULTPACK_AUDIT_LOG")
			}

			var filter audit.ExportFilter
			filter.Operation = operation
			filter.KeyFingerprint = keyFP
			if since != "" {
				t, err := parseAuditTime(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				filter.Since = &t
			}
			if until != "" {
				t, err := parseAuditTime(until)
				if err != nil {
					return fmt.Errorf("--until: %w", err)
				}
				filter.Until = &t
			}

			entries, err := audit.ReadAuditLog(logPath, &filter)
			if err != nil {
				return fmt.Errorf("read audit log: %w", err)
			}

			var out []byte
			switch format {
			case "csv":
				out, err = audit.ExportCSV(entries)
			case "json":
				out, err = audit.ExportJSON(entries, "  ")
			default:
				return fmt.Errorf("unsupported format %q; use csv or json", format)
			}
			if err != nil {
				return err
			}

			if _, err := os.Stdout.Write(out); err != nil {
				return err
			}

			if printer.Mode == OutputJSON && format != "json" {
				// User asked for --json global flag; we already wrote CSV. Ignore.
			}
			_ = printer
			return nil
		},
	}

	cmd.Flags().StringVar(&logPath, "log", "", "audit log file (default: --audit-log or VAULTPACK_AUDIT_LOG)")
	cmd.Flags().StringVar(&format, "format", "json", "output format: csv, json")
	cmd.Flags().StringVar(&since, "since", "", "include entries on or after this time (RFC3339 or 2006-01-02)")
	cmd.Flags().StringVar(&until, "until", "", "include entries before this time (RFC3339 or 2006-01-02)")
	cmd.Flags().StringVar(&operation, "operation", "", "filter by operation name (e.g. protect, decrypt)")
	cmd.Flags().StringVar(&keyFP, "key-fingerprint", "", "filter by key fingerprint (substring match)")

	return cmd
}

func parseAuditTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q (use RFC3339 or 2006-01-02)", s)
}
