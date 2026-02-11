package cli

import (
	"os"
	"sync"

	"github.com/Skpow1234/Vaultpack/internal/audit"
)

var (
	auditLogger     audit.Logger
	auditLoggerOnce sync.Once
)

// getAuditLogger returns the global audit logger (file or nop). Resolves path from flag or VAULTPACK_AUDIT_LOG.
func getAuditLogger() audit.Logger {
	auditLoggerOnce.Do(func() {
		path := flagAuditLog
		if path == "" {
			path = os.Getenv("VAULTPACK_AUDIT_LOG")
		}
		if path == "" {
			auditLogger = &audit.NopLogger{}
			return
		}
		l, err := audit.NewFileLogger(path)
		if err != nil {
			auditLogger = &audit.NopLogger{}
			return
		}
		auditLogger = l
	})
	return auditLogger
}

// auditLog writes one audit entry. Safe to call with nil logger (nop).
func auditLog(operation, inputFile, outputFile, bundleHash, keyFingerprint string, success bool, errMsg string) {
	getAuditLogger().Log(&audit.Entry{
		Operation:      operation,
		InputFile:      inputFile,
		OutputFile:     outputFile,
		BundleHash:     bundleHash,
		KeyFingerprint: keyFingerprint,
		Success:        success,
		Error:          errMsg,
	})
}
