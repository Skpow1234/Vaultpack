package serve

import (
	"errors"
	"fmt"
	"os"
	"os/user"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/kms"
	"github.com/Skpow1234/Vaultpack/internal/policy"
)

func (s *Server) enforcePolicy(op, bundlePath string, m *bundle.Manifest) error {
	if s.policy == nil {
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
	dec, err := s.policy.Evaluate(ctx)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}
	if dec.Allowed() {
		return nil
	}
	reason := dec.Reason
	if reason == "" {
		reason = "denied by policy"
	}
	s.auditEntry(audit.OpPolicyDeny, bundlePath, "", "", false,
		fmt.Sprintf("op=%s rule=%q reason=%s", op, dec.MatchedRule, reason))
	return fmt.Errorf("policy denied: %s (rule: %q)", reason, dec.MatchedRule)
}

func (s *Server) auditEntry(op, input, output, keyFP string, ok bool, errMsg string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Log(&audit.Entry{
		Operation:      op,
		InputFile:      input,
		OutputFile:     output,
		KeyFingerprint: keyFP,
		Success:        ok,
		Error:          errMsg,
	})
}

func (s *Server) unwrapKMS(provider string, wrapped []byte, keyID string) ([]byte, error) {
	if provider == "" {
		return nil, errors.New("kms provider required")
	}
	cacheKey := CacheKey(provider, keyID, wrapped)
	if dek, ok := s.kms.Get(cacheKey); ok {
		return dek, nil
	}
	p := kms.Get(provider)
	if p == nil {
		return nil, fmt.Errorf("KMS provider %q not found", provider)
	}
	dek, err := p.UnwrapDEK(wrapped, keyID)
	if err != nil {
		return nil, err
	}
	s.kms.Put(cacheKey, dek)
	return dek, nil
}
