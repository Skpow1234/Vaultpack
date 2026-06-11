package serve

import (
	"crypto/subtle"
	"net/http"
)

type authMiddleware struct {
	tokenBytes []byte
	oidc       *oidcValidator
}

func newAuthMiddleware(token string, oidc *oidcValidator) *authMiddleware {
	a := &authMiddleware{oidc: oidc}
	if token != "" {
		a.tokenBytes = []byte(token)
	}
	return a
}

// check returns true if the request is allowed. The decision is:
//
//   - If a bearer token is configured, it must match exactly (constant time), OR
//     OIDC JWT validation must succeed when OIDC is configured.
//   - If no bearer token is configured, OIDC JWT alone can authenticate.
//   - Otherwise we rely on mTLS (handled by TLS layer) or AuthDisabled.
func (a *authMiddleware) check(r *http.Request) bool {
	got := bearerToken(r)
	if got == "" {
		return len(a.tokenBytes) == 0 && a.oidc == nil
	}
	if len(a.tokenBytes) > 0 && subtle.ConstantTimeCompare([]byte(got), a.tokenBytes) == 1 {
		return true
	}
	if a.oidc != nil && a.oidc.validate(got) == nil {
		return true
	}
	return len(a.tokenBytes) == 0 && a.oidc == nil
}
