package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/rego"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// regoEvaluator wraps a compiled OPA query so we can satisfy Evaluator.
type regoEvaluator struct {
	prepared rego.PreparedEvalQuery
	source   string
}

// loadRego compiles a .rego source file. The policy is expected to define a
// boolean rule named `allow` in package `vaultpack` (or `vaultpack.policy`):
//
//	package vaultpack
//
//	default allow := false
//
//	allow {
//	    input.operation == "decrypt"
//	    input.user == "alice"
//	}
//
// An optional `deny_reason` string rule can supply a human-readable rejection
// message.
func loadRego(path string, data []byte) (Evaluator, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q, err := rego.New(
		rego.Query("data.vaultpack"),
		rego.Module(path, string(data)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile rego %s: %w", path, err)
	}
	return &regoEvaluator{prepared: q, source: path}, nil
}

// Evaluate sends the Context as input to the prepared OPA query and reads
// the `allow` and optional `deny_reason` values out of the result.
func (r *regoEvaluator) Evaluate(ctx Context) (Decision, error) {
	in := map[string]any{
		"operation":   ctx.Operation,
		"user":        ctx.User,
		"hostname":    ctx.Hostname,
		"bundle_path": ctx.BundlePath,
		"now":         ctx.Now.UTC().Format(time.RFC3339),
		"weekday":     ctx.Now.UTC().Weekday().String(),
	}
	if ctx.Manifest != nil {
		m := ctx.Manifest
		mIn := map[string]any{
			"aead":                m.Encryption.AEAD,
			"key_id_digest":       m.Encryption.KeyID.DigestB64,
			"kms_key_id":          m.Encryption.KmsKeyID,
			"plaintext_digest":    m.Plaintext.DigestB64,
			"plaintext_algo":      m.Plaintext.Algo,
			"signature_algo":      "",
			"signed":              m.SignatureAlgo != nil && *m.SignatureAlgo != "",
			"recipient_count":    recipientCount(m),
			"recipient_fingerprints": collectFingerprints(m),
		}
		if m.SignatureAlgo != nil {
			mIn["signature_algo"] = *m.SignatureAlgo
		}
		if m.Encryption.Hybrid != nil {
			mIn["hybrid_scheme"] = m.Encryption.Hybrid.Scheme
		}
		in["manifest"] = mIn
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results, err := r.prepared.Eval(timeoutCtx, rego.EvalInput(in))
	if err != nil {
		return Decision{}, fmt.Errorf("rego eval: %w", err)
	}
	if len(results) == 0 {
		return Decision{Action: ActionDeny, Reason: "rego: no result"}, nil
	}

	// results[0].Expressions[0].Value is the entire `data.vaultpack` document.
	doc, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{Action: ActionDeny, Reason: "rego: result not an object"}, nil
	}
	allow, _ := doc["allow"].(bool)
	reason, _ := doc["deny_reason"].(string)
	if allow {
		return Decision{Action: ActionAllow, MatchedRule: "rego:allow", Reason: reason}, nil
	}
	if reason == "" {
		reason = "rego: allow == false"
	}
	return Decision{Action: ActionDeny, MatchedRule: "rego:deny", Reason: reason}, nil
}

func collectFingerprints(m *bundle.Manifest) []string {
	out := make([]string, 0)
	if m.Encryption.Hybrid == nil {
		return out
	}
	if m.Encryption.Hybrid.RecipientFingerprintB64 != "" {
		out = append(out, m.Encryption.Hybrid.RecipientFingerprintB64)
	}
	for _, r := range m.Encryption.Hybrid.Recipients {
		if r.FingerprintB64 != "" {
			out = append(out, r.FingerprintB64)
		}
	}
	return out
}
