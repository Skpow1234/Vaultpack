package serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCOptions configures optional JWT bearer authentication (beyond a static token).
type OIDCOptions struct {
	Issuer   string
	Audience string
	JWKSURL  string // optional; derived from Issuer when empty
}

type oidcValidator struct {
	opts    OIDCOptions
	mu      sync.RWMutex
	keys    map[string]any // kid -> *rsa.PublicKey or *ecdsa.PublicKey
	fetched time.Time
}

func newOIDCValidator(opts OIDCOptions) (*oidcValidator, error) {
	if opts.Issuer == "" {
		return nil, errors.New("serve: --oidc-issuer is required when OIDC auth is enabled")
	}
	if opts.Audience == "" {
		return nil, errors.New("serve: --oidc-audience is required when OIDC auth is enabled")
	}
	v := &oidcValidator{opts: opts}
	if err := v.refreshKeys(); err != nil {
		return nil, fmt.Errorf("serve: load OIDC JWKS: %w", err)
	}
	return v, nil
}

func (v *oidcValidator) validate(token string) error {
	if token == "" {
		return errors.New("empty token")
	}
	if err := v.ensureKeys(); err != nil {
		return err
	}
	v.mu.RLock()
	keys := v.keys
	v.mu.RUnlock()

	_, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid != "" {
			if k, ok := keys[kid]; ok {
				return k, nil
			}
		}
		for _, k := range keys {
			return k, nil
		}
		return nil, errors.New("no matching JWKS key")
	},
		jwt.WithIssuer(v.opts.Issuer),
		jwt.WithAudience(v.opts.Audience),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	)
	return err
}

func (v *oidcValidator) ensureKeys() error {
	v.mu.RLock()
	stale := v.fetched.IsZero() || time.Since(v.fetched) > time.Hour
	v.mu.RUnlock()
	if !stale {
		return nil
	}
	return v.refreshKeys()
}

func (v *oidcValidator) refreshKeys() error {
	jwksURL := v.opts.JWKSURL
	if jwksURL == "" {
		cfgURL := strings.TrimRight(v.opts.Issuer, "/") + "/.well-known/openid-configuration"
		cfg, err := fetchJSON(cfgURL)
		if err != nil {
			return err
		}
		jwksURL, _ = cfg["jwks_uri"].(string)
		if jwksURL == "" {
			return fmt.Errorf("no jwks_uri in %s", cfgURL)
		}
	}
	doc, err := fetchJSON(jwksURL)
	if err != nil {
		return err
	}
	keysRaw, _ := doc["keys"].([]any)
	if len(keysRaw) == 0 {
		return errors.New("JWKS contains no keys")
	}
	parsed := make(map[string]any)
	for _, item := range keysRaw {
		jwk, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kty, _ := jwk["kty"].(string)
		kid, _ := jwk["kid"].(string)
		var pub any
		var err error
		switch kty {
		case "RSA":
			pub, err = parseRSAPublicKey(jwk)
		case "EC":
			pub, err = parseECPublicKey(jwk)
		default:
			continue
		}
		if err != nil {
			continue
		}
		if kid == "" {
			kid = fmt.Sprintf("key-%d", len(parsed))
		}
		parsed[kid] = pub
	}
	if len(parsed) == 0 {
		return errors.New("JWKS: no supported RSA/EC keys")
	}
	v.mu.Lock()
	v.keys = parsed
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func fetchJSON(url string) (map[string]any, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseRSAPublicKey(jwk map[string]any) (*rsa.PublicKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, errors.New("missing RSA n/e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}, nil
}

func parseECPublicKey(jwk map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, errors.New("missing EC x/y")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
