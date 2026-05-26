package cli

import (
	"errors"
	"fmt"
	"os"
	"os/user"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/policy"
)

// ErrPolicyDenied is returned by enforcePolicy when the active policy rejects
// the requested operation. CLI commands surface it directly so the user sees
// the policy's reason verbatim.
var ErrPolicyDenied = errors.New("policy denied")

// enforcePolicy consults the global policy (if any) before an operation runs.
// If the policy denies the action, an audit entry is written and an error is
// returned. When no policy is loaded, every call returns nil.
//
// Pass a nil manifest for operations that don't yet have one (protect, keygen).
func enforcePolicy(op, bundlePath string, m *bundle.Manifest) error {
	ev := policy.Global()
	if ev == nil {
		return nil
	}
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	host, _ := os.Hostname()
	ctx := policy.Context{
		Operation:  op,
		BundlePath: bundlePath,
		Manifest:   m,
		User:       uname,
		Hostname:   host,
	}
	dec, err := ev.Evaluate(ctx)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}
	if dec.Allowed() {
		return nil
	}
	// Log the denial. The original operation's audit entry will still fire
	// (with success=false) via the wrapping defer in each command.
	reason := dec.Reason
	if reason == "" {
		reason = "denied by policy"
	}
	auditLog(audit.OpPolicyDeny, bundlePath, "", "", "", false,
		fmt.Sprintf("op=%s rule=%q reason=%s", op, dec.MatchedRule, reason))
	return fmt.Errorf("%w: %s (rule: %q)", ErrPolicyDenied, reason, dec.MatchedRule)
}
