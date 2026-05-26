package serve

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type authMiddleware struct {
	tokenBytes []byte // empty == no token required (mTLS or AuthDisabled covers it)
}

func newAuthMiddleware(token string) *authMiddleware {
	if token == "" {
		return &authMiddleware{}
	}
	return &authMiddleware{tokenBytes: []byte(token)}
}

// check returns true if the request is allowed. The decision is:
//
//   - If a bearer token is configured, it must match exactly (in constant time).
//   - Otherwise, we rely on mTLS (handled by the TLS layer) or
//     AuthDisabled (the operator opted out).
//
// Either way, we count an attempt for the metrics layer to record.
func (a *authMiddleware) check(r *http.Request) bool {
	if len(a.tokenBytes) == 0 {
		// No bearer required — either mTLS or AuthDisabled is in force.
		return true
	}
	got := bearerToken(r)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), a.tokenBytes) == 1
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
