package transparency

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadOIDCToken resolves an OIDC ID token from (in order): a file path, the
// VAULTPACK_OIDC_TOKEN environment variable, then SIGSTORE_ID_TOKEN (the
// convention used by cosign and CI runners).
func LoadOIDCToken(filePath string) (string, error) {
	if filePath != "" {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read oidc token: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if v := os.Getenv("VAULTPACK_OIDC_TOKEN"); v != "" {
		return strings.TrimSpace(v), nil
	}
	if v := os.Getenv("SIGSTORE_ID_TOKEN"); v != "" {
		return strings.TrimSpace(v), nil
	}
	return "", errors.New("no OIDC token: pass --oidc-token-file, or set VAULTPACK_OIDC_TOKEN / SIGSTORE_ID_TOKEN")
}

// OIDCClaims is the subset of standard JWT claims we need from the ID token
// to populate the manifest's Identity / OIDCIssuer fields and to build the
// proof-of-possession signature.
type OIDCClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Email   string `json:"email"`
	// SAN URI alternative for workload identities (GitHub OIDC etc).
	URI string `json:"uri,omitempty"`
}

// ParseOIDCClaims pulls the standard claims out of a JWT without verifying
// signature. Fulcio is the one verifying — we only need the values for the
// manifest entry and the PoP message.
func ParseOIDCClaims(token string) (OIDCClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return OIDCClaims{}, errors.New("invalid jwt: missing dots")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some tokens use std padded base64; retry.
		if alt, err2 := base64.StdEncoding.DecodeString(parts[1]); err2 == nil {
			payload = alt
		} else {
			return OIDCClaims{}, fmt.Errorf("decode jwt body: %w", err)
		}
	}
	var claims OIDCClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return OIDCClaims{}, fmt.Errorf("parse jwt body: %w", err)
	}
	return claims, nil
}

// SubjectFromClaims returns the identifier Fulcio will sign over (email
// preferred; falls back to SAN URI or subject claim).
func SubjectFromClaims(c OIDCClaims) string {
	switch {
	case c.Email != "":
		return c.Email
	case c.URI != "":
		return c.URI
	default:
		return c.Subject
	}
}
