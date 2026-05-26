package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// --- helpers ---

func ptrBool(b bool) *bool { return &b }
func ptrInt(i int) *int    { return &i }
func strPtr(s string) *string { return &s }

func sampleManifest() *bundle.Manifest {
	algo := "ed25519"
	signedAt := "2026-01-01T00:00:00Z"
	return &bundle.Manifest{
		Version: bundle.ManifestVersionV2,
		Plaintext: bundle.PlaintextHash{
			Algo:      "sha256",
			DigestB64: "AAAA",
		},
		Encryption: bundle.EncryptionMeta{
			AEAD:     "aes-256-gcm",
			KmsKeyID: "arn:aws:kms:us-east-1:111111111111:key/prod-abc",
			KeyID:    bundle.KeyID{Algo: "sha256", DigestB64: "BBBB"},
			Hybrid: &bundle.HybridMeta{
				Scheme:                  "rsa-oaep-2048",
				RecipientFingerprintB64: "alice-fp",
			},
		},
		SignatureAlgo: &algo,
		SignedAt:      &signedAt,
	}
}

// --- engine ---

func TestPolicy_DefaultAllow(t *testing.T) {
	p := &Policy{}
	d, err := p.Evaluate(Context{Operation: "decrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Errorf("expected default allow, got %s", d.Action)
	}
}

func TestPolicy_DefaultDeny(t *testing.T) {
	p := &Policy{Default: ActionDeny}
	d, err := p.Evaluate(Context{Operation: "decrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Errorf("expected default deny, got %s", d.Action)
	}
}

func TestPolicy_OperationMatch(t *testing.T) {
	p := &Policy{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "no-decrypt", Action: ActionDeny, Reason: "decrypts blocked",
				When: Condition{Operation: []string{"decrypt"}}},
		},
	}
	d, _ := p.Evaluate(Context{Operation: "decrypt"})
	if d.Allowed() {
		t.Error("decrypt should be denied")
	}
	d, _ = p.Evaluate(Context{Operation: "inspect"})
	if !d.Allowed() {
		t.Error("inspect should still be allowed")
	}
}

func TestPolicy_UserMatch(t *testing.T) {
	p := &Policy{
		Default: ActionDeny,
		Rules: []Rule{
			{Name: "alice-only", Action: ActionAllow,
				When: Condition{User: "alice"}},
		},
	}
	if d, _ := p.Evaluate(Context{Operation: "decrypt", User: "alice"}); !d.Allowed() {
		t.Error("alice should be allowed")
	}
	if d, _ := p.Evaluate(Context{Operation: "decrypt", User: "bob"}); d.Allowed() {
		t.Error("bob should be denied (default)")
	}
}

func TestPolicy_KMSKeyIDRegex(t *testing.T) {
	p := &Policy{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "block-dev-keys", Action: ActionDeny, Reason: "dev keys not decryptable in prod",
				When: Condition{
					Operation:       []string{"decrypt"},
					KMSKeyIDMatches: `.*/dev-.*`,
				}},
		},
	}
	m := sampleManifest()
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); !d.Allowed() {
		t.Error("prod key should not match dev regex")
	}
	m.Encryption.KmsKeyID = "arn:aws:kms:us-east-1:111111111111:key/dev-xyz"
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); d.Allowed() {
		t.Error("dev key should be denied")
	}
}

func TestPolicy_RecipientFingerprint(t *testing.T) {
	p := &Policy{
		Default: ActionDeny,
		Rules: []Rule{
			{Name: "approved-recipients", Action: ActionAllow,
				When: Condition{RecipientFingerprintIn: []string{"alice-fp", "bob-fp"}}},
		},
	}
	m := sampleManifest()
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); !d.Allowed() {
		t.Error("alice-fp should pass")
	}
	m.Encryption.Hybrid.RecipientFingerprintB64 = "carol-fp"
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); d.Allowed() {
		t.Error("carol-fp should be denied")
	}
}

func TestPolicy_IsSigned(t *testing.T) {
	// Rule "deny unsigned decrypts" matches when is_signed == false.
	unsigned := false
	p := &Policy{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "deny-unsigned-decrypt", Action: ActionDeny, Reason: "unsigned bundle",
				When: Condition{Operation: []string{"decrypt"}, IsSigned: &unsigned}},
		},
	}
	m := sampleManifest()
	m.SignatureAlgo = nil
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); d.Allowed() {
		t.Error("unsigned bundle should be denied")
	}
	m.SignatureAlgo = strPtr("ed25519")
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Manifest: m}); !d.Allowed() {
		t.Error("signed bundle should be allowed")
	}
}

func TestPolicy_TimeWindow(t *testing.T) {
	p := &Policy{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "after-hours-block", Action: ActionDeny, Reason: "after hours",
				When: Condition{
					Operation:  []string{"decrypt"},
					TimeWindow: &TimeWindow{From: "00:00", To: "06:00", Timezone: "UTC"},
				}},
		},
	}
	earlyMorning := time.Date(2026, 5, 26, 4, 30, 0, 0, time.UTC)
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Now: earlyMorning}); d.Allowed() {
		t.Error("4:30 UTC should be in the deny window")
	}
	midday := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	if d, _ := p.Evaluate(Context{Operation: "decrypt", Now: midday}); !d.Allowed() {
		t.Error("midday should be allowed")
	}
}

func TestPolicy_TimeWindow_WrapsMidnight(t *testing.T) {
	p := &Policy{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "night-allow", Action: ActionAllow,
				When: Condition{TimeWindow: &TimeWindow{From: "22:00", To: "06:00"}}},
		},
	}
	c := Condition{TimeWindow: &TimeWindow{From: "22:00", To: "06:00"}}
	for _, hr := range []int{22, 23, 0, 5} {
		ok, err := c.matches(Context{Now: time.Date(2026, 5, 26, hr, 30, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("hour %d should match wrapped window", hr)
		}
	}
	ok, _ := c.matches(Context{Now: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)})
	if ok {
		t.Error("noon should not match 22:00-06:00")
	}
	_ = p
}

func TestPolicy_Weekday(t *testing.T) {
	c := Condition{Weekday: []string{"Saturday", "Sunday"}}
	sat := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) // Saturday
	mon := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) // Monday
	if ok, _ := c.matches(Context{Now: sat}); !ok {
		t.Error("Saturday should match")
	}
	if ok, _ := c.matches(Context{Now: mon}); ok {
		t.Error("Monday should not match")
	}
}

func TestPolicy_RuleOrderFirstMatchWins(t *testing.T) {
	p := &Policy{
		Default: ActionDeny,
		Rules: []Rule{
			{Name: "allow-decrypt", Action: ActionAllow,
				When: Condition{Operation: []string{"decrypt"}}},
			{Name: "deny-all", Action: ActionDeny}, // never reached
		},
	}
	d, _ := p.Evaluate(Context{Operation: "decrypt"})
	if !d.Allowed() {
		t.Error("first matching rule (allow) should win")
	}
	if d.MatchedRule != "allow-decrypt" {
		t.Errorf("expected allow-decrypt rule, got %q", d.MatchedRule)
	}
}

// --- loader ---

func TestLoad_YAML(t *testing.T) {
	dir := t.TempDir()
	yamlSrc := `
version: 1
default: deny
rules:
  - name: alice-can-decrypt
    action: allow
    when:
      operation: [decrypt]
      user: alice
  - name: block-weekends
    action: deny
    reason: "no work on weekends"
    when:
      weekday: [Saturday, Sunday]
`
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, ok := ev.(*Policy)
	if !ok {
		t.Fatal("expected *Policy")
	}
	if len(p.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(p.Rules))
	}
	if p.Default != ActionDeny {
		t.Errorf("default=%q, want deny", p.Default)
	}
	d, _ := p.Evaluate(Context{Operation: "decrypt", User: "alice"})
	if !d.Allowed() {
		t.Error("alice/decrypt should be allowed")
	}
	d, _ = p.Evaluate(Context{Operation: "decrypt", User: "bob"})
	if d.Allowed() {
		t.Error("bob/decrypt should be denied")
	}
}

func TestLoad_JSON(t *testing.T) {
	dir := t.TempDir()
	jsonSrc := `{
  "version": 1,
  "default": "allow",
  "rules": [
    {"name": "deny-inspect", "action": "deny", "when": {"operation": ["inspect"]}}
  ]
}`
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(jsonSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, _ := ev.Evaluate(Context{Operation: "inspect"})
	if d.Allowed() {
		t.Error("inspect should be denied")
	}
}

func TestLoad_InvalidVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte("version: 99\nrules: []\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unsupported policy version") {
		t.Errorf("expected unsupported version error, got: %v", err)
	}
}

func TestLoad_InvalidRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	os.WriteFile(path, []byte(`
version: 1
rules:
  - action: deny
    when:
      user_matches: "["
`), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("expected regex error, got: %v", err)
	}
}

func TestLoad_UnknownExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.txt")
	os.WriteFile(path, []byte("ignored"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unsupported policy file extension") {
		t.Errorf("expected unsupported extension error, got: %v", err)
	}
}

// --- Rego ---

func TestLoad_Rego_AllowDeny(t *testing.T) {
	dir := t.TempDir()
	// v0-style Rego (no `if` keyword) works under both v0 and v1 OPA parsers.
	src := `package vaultpack

default allow = false

allow {
    input.operation == "decrypt"
    input.user == "alice"
}

deny_reason = "not alice or not decrypt" {
    not allow
}
`
	path := filepath.Join(dir, "p.rego")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, err := Load(path)
	if err != nil {
		t.Fatalf("load rego: %v", err)
	}
	d, err := ev.Evaluate(Context{Operation: "decrypt", User: "alice"})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !d.Allowed() {
		t.Errorf("alice/decrypt should be allowed, got %s (%s)", d.Action, d.Reason)
	}
	d, _ = ev.Evaluate(Context{Operation: "decrypt", User: "bob"})
	if d.Allowed() {
		t.Error("bob should be denied")
	}
	if !strings.Contains(d.Reason, "not alice") {
		t.Errorf("expected deny_reason, got %q", d.Reason)
	}
}

// --- Global / Enforce ---

func TestEnforce_NoGlobalAllows(t *testing.T) {
	SetGlobal(nil) // ensure clean
	d, err := Enforce(Context{Operation: "decrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Error("with no policy, should allow")
	}
}

func TestEnforce_WithGlobalDeny(t *testing.T) {
	t.Cleanup(func() { SetGlobal(nil) })
	SetGlobal(&Policy{
		Default: ActionDeny,
	})
	d, _ := Enforce(Context{Operation: "decrypt"})
	if d.Allowed() {
		t.Error("global deny should block")
	}
}
