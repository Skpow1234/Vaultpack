// Package policy implements VaultPack's RBAC / rules engine.
//
// A Policy is a YAML or JSON document containing a list of Rules. Each Rule
// has an Action ("allow" or "deny"), an optional human-readable Reason, and
// a set of conditions in the When block. The engine evaluates rules in order
// against the current Context (operation, bundle path, manifest, environment)
// and stops at the first match. If no rule matches, the policy's Default
// action applies (defaults to "allow").
//
// Native conditions cover the common cases (operation, user/hostname, weekday,
// time window, KMS key ID, recipient fingerprint, plaintext digest, cipher,
// signature algo, hybrid scheme). For richer logic, a `.rego` file may be
// loaded via OPA — see rego.go.
package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// SchemaVersion is the current policy schema version.
const SchemaVersion = 1

// Action is the result of evaluating a rule (or the default).
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Policy is the top-level document loaded from YAML or JSON.
type Policy struct {
	// Version is the schema version. 1 is currently the only supported value.
	Version int `yaml:"version" json:"version"`
	// Default is the action applied when no rule matches. Defaults to "allow".
	Default Action `yaml:"default,omitempty" json:"default,omitempty"`
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// Rule is a single decision: an action plus the conditions under which it fires.
type Rule struct {
	Name   string    `yaml:"name,omitempty" json:"name,omitempty"`
	Action Action    `yaml:"action" json:"action"`
	Reason string    `yaml:"reason,omitempty" json:"reason,omitempty"`
	When   Condition `yaml:"when,omitempty" json:"when,omitempty"`
}

// Condition captures all the supported predicates. An empty Condition matches
// every Context; non-empty fields are ANDed together — every populated check
// must pass for the rule to fire.
type Condition struct {
	// Operation: list of operations this rule applies to ("decrypt", "verify", ...).
	// When empty, the rule applies to every operation.
	Operation []string `yaml:"operation,omitempty" json:"operation,omitempty"`

	// Principal predicates.
	User         string `yaml:"user,omitempty" json:"user,omitempty"`
	UserMatches  string `yaml:"user_matches,omitempty" json:"user_matches,omitempty"`
	Hostname     string `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	HostnameMatches string `yaml:"hostname_matches,omitempty" json:"hostname_matches,omitempty"`

	// Temporal predicates.
	Weekday    []string    `yaml:"weekday,omitempty" json:"weekday,omitempty"`        // e.g. ["Monday", "Tuesday"]
	TimeWindow *TimeWindow `yaml:"time_window,omitempty" json:"time_window,omitempty"`

	// Bundle / manifest predicates.
	BundlePathMatches      string   `yaml:"bundle_path_matches,omitempty" json:"bundle_path_matches,omitempty"`
	KMSKeyID               string   `yaml:"kms_key_id,omitempty" json:"kms_key_id,omitempty"`
	KMSKeyIDMatches        string   `yaml:"kms_key_id_matches,omitempty" json:"kms_key_id_matches,omitempty"`
	CipherIn               []string `yaml:"cipher_in,omitempty" json:"cipher_in,omitempty"`
	HybridSchemeMatches    string   `yaml:"hybrid_scheme_matches,omitempty" json:"hybrid_scheme_matches,omitempty"`
	SignatureAlgoIn        []string `yaml:"signature_algo_in,omitempty" json:"signature_algo_in,omitempty"`
	SignatureAlgoNotIn     []string `yaml:"signature_algo_not_in,omitempty" json:"signature_algo_not_in,omitempty"`
	// IsSigned (when set) matches bundles whose signature presence equals the value.
	// Example: to deny unsigned decrypts, write `action: deny` with `is_signed: false`
	// (the rule fires on unsigned bundles).
	IsSigned               *bool    `yaml:"is_signed,omitempty" json:"is_signed,omitempty"`
	RecipientFingerprintIn []string `yaml:"recipient_fingerprint_in,omitempty" json:"recipient_fingerprint_in,omitempty"`
	PlaintextDigestIn      []string `yaml:"plaintext_digest_in,omitempty" json:"plaintext_digest_in,omitempty"`
	MinRecipients          *int     `yaml:"min_recipients,omitempty" json:"min_recipients,omitempty"`
	MaxRecipients          *int     `yaml:"max_recipients,omitempty" json:"max_recipients,omitempty"`
}

// TimeWindow is an inclusive time-of-day range in HH:MM format,
// evaluated in the location given by Timezone (default UTC).
type TimeWindow struct {
	From     string `yaml:"from" json:"from"`         // "08:00"
	To       string `yaml:"to" json:"to"`             // "18:00"
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"` // IANA zone, defaults to "UTC"
}

// Context is the dynamic input the engine evaluates rules against.
type Context struct {
	Operation  string
	BundlePath string
	Manifest   *bundle.Manifest
	User       string
	Hostname   string
	Now        time.Time // defaulted to time.Now().UTC() if zero
}

// Decision is the outcome of evaluating a policy against a context.
type Decision struct {
	Action     Action
	Reason     string
	MatchedRule string // name of the rule that produced the decision, "" if default
}

// Allowed returns true if Action == "allow".
func (d Decision) Allowed() bool { return d.Action == ActionAllow }

// Evaluate iterates the policy's rules and returns the first matching decision.
// Falls back to Policy.Default (or "allow") if no rule matches.
func (p *Policy) Evaluate(ctx Context) (Decision, error) {
	if ctx.Now.IsZero() {
		ctx.Now = time.Now().UTC()
	}
	for _, r := range p.Rules {
		match, err := r.When.matches(ctx)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if !match {
			continue
		}
		return Decision{
			Action:      r.Action,
			Reason:      r.Reason,
			MatchedRule: r.Name,
		}, nil
	}
	def := p.Default
	if def == "" {
		def = ActionAllow
	}
	return Decision{Action: def, Reason: "default"}, nil
}

// Validate checks the policy for structural problems before evaluation.
func (p *Policy) Validate() error {
	if p.Version != 0 && p.Version != SchemaVersion {
		return fmt.Errorf("unsupported policy version %d (want %d)", p.Version, SchemaVersion)
	}
	if p.Default != "" && p.Default != ActionAllow && p.Default != ActionDeny {
		return fmt.Errorf("invalid default %q (must be allow|deny)", p.Default)
	}
	for i, r := range p.Rules {
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return fmt.Errorf("rule[%d] %q: invalid action %q", i, r.Name, r.Action)
		}
		if err := r.When.validate(); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, r.Name, err)
		}
	}
	return nil
}

// --- Condition matchers ---

// matches returns true if every populated field in the Condition is satisfied
// by ctx. An empty Condition matches every Context.
func (c Condition) matches(ctx Context) (bool, error) {
	if len(c.Operation) > 0 && !stringInSlice(ctx.Operation, c.Operation) {
		return false, nil
	}
	if c.User != "" && ctx.User != c.User {
		return false, nil
	}
	if c.UserMatches != "" {
		ok, err := regexMatch(c.UserMatches, ctx.User)
		if err != nil || !ok {
			return false, err
		}
	}
	if c.Hostname != "" && ctx.Hostname != c.Hostname {
		return false, nil
	}
	if c.HostnameMatches != "" {
		ok, err := regexMatch(c.HostnameMatches, ctx.Hostname)
		if err != nil || !ok {
			return false, err
		}
	}
	if len(c.Weekday) > 0 {
		day := ctx.Now.Weekday().String()
		if !stringInSliceFold(day, c.Weekday) {
			return false, nil
		}
	}
	if c.TimeWindow != nil {
		ok, err := c.TimeWindow.contains(ctx.Now)
		if err != nil || !ok {
			return false, err
		}
	}
	if c.BundlePathMatches != "" {
		ok, err := regexMatch(c.BundlePathMatches, ctx.BundlePath)
		if err != nil || !ok {
			return false, err
		}
	}
	// Manifest-derived predicates: all silently skipped when manifest is nil
	// (e.g. policy applied to a "protect" op that hasn't built a manifest yet).
	if ctx.Manifest != nil {
		m := ctx.Manifest
		if c.KMSKeyID != "" && m.Encryption.KmsKeyID != c.KMSKeyID {
			return false, nil
		}
		if c.KMSKeyIDMatches != "" {
			ok, err := regexMatch(c.KMSKeyIDMatches, m.Encryption.KmsKeyID)
			if err != nil || !ok {
				return false, err
			}
		}
		if len(c.CipherIn) > 0 && !stringInSlice(m.Encryption.AEAD, c.CipherIn) {
			return false, nil
		}
		if c.HybridSchemeMatches != "" {
			scheme := ""
			if m.Encryption.Hybrid != nil {
				scheme = m.Encryption.Hybrid.Scheme
			}
			ok, err := regexMatch(c.HybridSchemeMatches, scheme)
			if err != nil || !ok {
				return false, err
			}
		}
		if c.IsSigned != nil {
			signed := m.SignatureAlgo != nil && *m.SignatureAlgo != ""
			if signed != *c.IsSigned {
				return false, nil
			}
		}
		if len(c.SignatureAlgoIn) > 0 {
			algo := ""
			if m.SignatureAlgo != nil {
				algo = *m.SignatureAlgo
			}
			if !stringInSlice(algo, c.SignatureAlgoIn) {
				return false, nil
			}
		}
		if len(c.SignatureAlgoNotIn) > 0 {
			algo := ""
			if m.SignatureAlgo != nil {
				algo = *m.SignatureAlgo
			}
			if stringInSlice(algo, c.SignatureAlgoNotIn) {
				return false, nil
			}
		}
		if len(c.RecipientFingerprintIn) > 0 {
			if !manifestHasAnyFingerprint(m, c.RecipientFingerprintIn) {
				return false, nil
			}
		}
		if len(c.PlaintextDigestIn) > 0 && !stringInSlice(m.Plaintext.DigestB64, c.PlaintextDigestIn) {
			return false, nil
		}
		if c.MinRecipients != nil {
			if recipientCount(m) < *c.MinRecipients {
				return false, nil
			}
		}
		if c.MaxRecipients != nil {
			if recipientCount(m) > *c.MaxRecipients {
				return false, nil
			}
		}
	}
	return true, nil
}

// validate checks regex patterns and time-window strings without needing a Context.
func (c Condition) validate() error {
	for _, p := range []string{c.UserMatches, c.HostnameMatches, c.BundlePathMatches, c.KMSKeyIDMatches, c.HybridSchemeMatches} {
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid regex %q: %w", p, err)
		}
	}
	if c.TimeWindow != nil {
		if _, err := parseHHMM(c.TimeWindow.From); err != nil {
			return fmt.Errorf("time_window.from: %w", err)
		}
		if _, err := parseHHMM(c.TimeWindow.To); err != nil {
			return fmt.Errorf("time_window.to: %w", err)
		}
		if c.TimeWindow.Timezone != "" {
			if _, err := time.LoadLocation(c.TimeWindow.Timezone); err != nil {
				return fmt.Errorf("time_window.timezone %q: %w", c.TimeWindow.Timezone, err)
			}
		}
	}
	for _, d := range c.Weekday {
		if !isWeekday(d) {
			return fmt.Errorf("weekday %q: not a valid day name", d)
		}
	}
	return nil
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func stringInSliceFold(s string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func regexMatch(pattern, s string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	return re.MatchString(s), nil
}

func manifestHasAnyFingerprint(m *bundle.Manifest, fps []string) bool {
	h := m.Encryption.Hybrid
	if h == nil {
		return false
	}
	if h.RecipientFingerprintB64 != "" && stringInSlice(h.RecipientFingerprintB64, fps) {
		return true
	}
	for _, r := range h.Recipients {
		if stringInSlice(r.FingerprintB64, fps) {
			return true
		}
	}
	return false
}

func recipientCount(m *bundle.Manifest) int {
	h := m.Encryption.Hybrid
	if h == nil {
		return 0
	}
	if n := len(h.Recipients); n > 0 {
		return n
	}
	if h.RecipientFingerprintB64 != "" || h.WrappedDEKB64 != "" || h.EphemeralPubKeyB64 != "" {
		return 1
	}
	return 0
}

// (TimeWindow.contains / parseHHMM / isWeekday) are defined in time.go for clarity.
var _ = sort.Strings // keep sort import available for future extensions
