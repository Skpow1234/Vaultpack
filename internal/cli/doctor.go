package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/spf13/cobra"
)

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Details string `json:"details,omitempty"`
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run local environment diagnostics",
		Long:  "Check local VaultPack runtime assumptions: Go/runtime info, configured KMS providers, audit/config env vars, and key-source/HSM availability hints.",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := runDoctorChecks()
			printer := NewPrinter(flagJSON, flagQuiet)
			if flagJSON {
				return printer.JSON(map[string]any{"ok": doctorOK(checks), "checks": checks})
			}
			for _, c := range checks {
				status := "OK"
				if !c.OK {
					status = "WARN"
				}
				printer.Human("%-5s  %-24s %s", status, c.Name, c.Details)
			}
			if !doctorOK(checks) {
				return fmt.Errorf("doctor found warnings")
			}
			return nil
		},
	}
	return cmd
}

func runDoctorChecks() []doctorCheck {
	checks := []doctorCheck{
		{Name: "runtime", OK: true, Details: runtime.GOOS + "/" + runtime.GOARCH + " " + runtime.Version()},
		{Name: "kms providers", OK: len(kms.Providers()) > 0, Details: fmt.Sprintf("%v", kms.Providers())},
	}
	if p := os.Getenv("VAULTPACK_AUDIT_LOG"); p != "" {
		checks = append(checks, doctorCheck{Name: "audit log env", OK: true, Details: p})
	} else {
		checks = append(checks, doctorCheck{Name: "audit log env", OK: true, Details: "not set (audit disabled unless --audit-log is used)"})
	}
	if p := os.Getenv("VAULTPACK_POLICY"); p != "" {
		checks = append(checks, doctorCheck{Name: "policy env", OK: true, Details: p})
	} else {
		checks = append(checks, doctorCheck{Name: "policy env", OK: true, Details: "not set"})
	}
	checks = append(checks,
		doctorCheck{Name: "key-source portable", OK: true, Details: "file:// env:// b64://"},
		doctorCheck{Name: "hsm/keychain backends", OK: true, Details: "pkcs11:// piv:// keychain:// dpapi:// reserved; platform builds required"},
	)
	return checks
}

func doctorOK(checks []doctorCheck) bool {
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}
