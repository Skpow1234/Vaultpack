// Package serve implements `vaultpack serve` — a long-running HTTP API
// that exposes the VaultPack SDK to remote clients. The wire contract is
// the same JSON envelope used by the C-shared library
// (`cmd/vaultpack-c`) and the WASM bindings: every endpoint takes a JSON
// body and returns a JSON object whose top-level shape is either
// `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.
package serve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/policy"
)

// Options configures a server. A zero value is invalid; use NewServer.
type Options struct {
	// Listen is one of:
	//   ":8443"               -> TCP (any host, port 8443)
	//   "127.0.0.1:8443"      -> TCP (loopback only)
	//   "unix:/var/run/vp.sock" -> UNIX domain socket (Unix only)
	Listen string

	// TLSCertFile / TLSKeyFile, if set, enable TLS.
	TLSCertFile string
	TLSKeyFile  string

	// TLSClientCAFile, if set, enables mutual TLS — clients must present
	// a certificate signed by one of the CAs in this PEM bundle.
	TLSClientCAFile string

	// AuthToken, if non-empty, requires every request (except /healthz and
	// /metrics) to carry `Authorization: Bearer <AuthToken>`. The
	// comparison is constant-time.
	AuthToken string

	// AuthDisabled is an explicit opt-out for local development. If both
	// AuthToken is empty AND TLSClientCAFile is empty, NewServer refuses
	// to start unless this is set to true.
	AuthDisabled bool

	// KMSCache configures the in-memory unwrap cache. Zero values mean
	// "use sensible defaults": TTL=5m, MaxEntries=1024.
	KMSCacheTTL     time.Duration
	KMSCacheMaxSize int

	// ReadTimeout / WriteTimeout bound per-request work. Defaults: 30s.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// MaxRequestBytes caps the size of any request body (default 64 MiB).
	// Protect/Decrypt embed plaintext or bundles as base64 so this is the
	// effective per-call payload limit.
	MaxRequestBytes int64

	// PolicyFile, if set, enforces RBAC rules on every /v1/* call (same as CLI --policy).
	PolicyFile string

	// AuditLogFile, if set, appends tamper-evident JSON-lines audit records.
	AuditLogFile string

	// RateLimitRPS limits requests per client IP (0 = disabled).
	RateLimitRPS float64
	// RateLimitBurst is the token bucket burst size (default: RPS+1).
	RateLimitBurst int

	// OIDC enables JWT bearer auth validated against an IdP JWKS.
	OIDC OIDCOptions
}

// Server is a configured but not-yet-started HTTP service.
type Server struct {
	opts      Options
	mux       *http.ServeMux
	httpSrv   *http.Server
	kms       *KMSCache
	metrics   *Metrics
	auth      *authMiddleware
	policy    policy.Evaluator
	audit     audit.Logger
	rateLimit *rateLimiter
}

// NewServer validates Options and returns a Server ready to call ListenAndServe.
func NewServer(opts Options) (*Server, error) {
	if opts.Listen == "" {
		return nil, errors.New("serve: Listen is required")
	}
	oidcEnabled := opts.OIDC.Issuer != "" || opts.OIDC.JWKSURL != ""
	if opts.AuthToken == "" && opts.TLSClientCAFile == "" && !opts.AuthDisabled && !oidcEnabled {
		return nil, errors.New("serve: refusing to start with no authentication; pass --auth-token, --tls-client-ca, --oidc-issuer, or --auth-disabled")
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 30 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 30 * time.Second
	}
	if opts.MaxRequestBytes == 0 {
		opts.MaxRequestBytes = 64 << 20 // 64 MiB
	}
	if opts.KMSCacheTTL == 0 {
		opts.KMSCacheTTL = 5 * time.Minute
	}
	if opts.KMSCacheMaxSize == 0 {
		opts.KMSCacheMaxSize = 1024
	}

	s := &Server{
		opts:    opts,
		mux:     http.NewServeMux(),
		kms:     NewKMSCache(opts.KMSCacheTTL, opts.KMSCacheMaxSize),
		metrics: NewMetrics(),
	}
	s.auth = newAuthMiddleware(opts.AuthToken)

	s.registerRoutes()
	s.httpSrv = &http.Server{
		Handler:           s.middleware(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       2 * time.Minute,
	}
	return s, nil
}

// Addr returns the configured listen address (helpful for tests).
func (s *Server) Addr() string { return s.opts.Listen }

// ListenAndServe binds the configured socket and serves until ctx is done.
// A nil ctx means "serve forever" (until process exit).
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// Serve hands the server a pre-built net.Listener. Used by tests and by
// callers that want to bind the socket themselves (e.g. systemd).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, ln)
}

func (s *Server) listen() (net.Listener, error) {
	if strings.HasPrefix(s.opts.Listen, "unix:") {
		path := strings.TrimPrefix(s.opts.Listen, "unix:")
		// Best-effort cleanup of stale sockets from prior runs.
		_ = os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("serve: listen unix %q: %w", path, err)
		}
		// 0600 by default — only the running user can connect.
		if err := os.Chmod(path, 0o600); err != nil {
			ln.Close()
			return nil, fmt.Errorf("serve: chmod %q: %w", path, err)
		}
		return ln, nil
	}
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("serve: listen tcp %q: %w", s.opts.Listen, err)
	}
	return ln, nil
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	tlsCfg, err := s.tlsConfig()
	if err != nil {
		ln.Close()
		return err
	}
	if tlsCfg != nil {
		s.httpSrv.TLSConfig = tlsCfg
		ln = tls.NewListener(ln, tlsCfg)
	}

	if ctx != nil {
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.httpSrv.Shutdown(shutdownCtx)
		}()
	}

	err = s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	if s.opts.TLSCertFile == "" && s.opts.TLSKeyFile == "" && s.opts.TLSClientCAFile == "" {
		return nil, nil
	}
	if s.opts.TLSCertFile == "" || s.opts.TLSKeyFile == "" {
		return nil, errors.New("serve: --tls-cert and --tls-key must be set together")
	}
	cert, err := tls.LoadX509KeyPair(s.opts.TLSCertFile, s.opts.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("serve: load TLS keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if s.opts.TLSClientCAFile != "" {
		pem, err := os.ReadFile(s.opts.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("serve: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("serve: no certs parsed from %q", s.opts.TLSClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// middleware composes the standard request pipeline: panic recovery,
// metrics, rate limit, max-body cap, auth.
func (s *Server) middleware(next http.Handler) http.Handler {
	return s.recover(s.metricsMW(s.rateLimitMW(s.maxBody(s.authGate(next)))))
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("panic: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxRequestBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and metrics endpoints are always reachable; they expose
		// no sensitive data and ops tooling depends on unauthenticated
		// scraping.
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if !s.auth.check(r) {
			s.metrics.AuthDenied.Add(1)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) metricsMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		s.metrics.observe(r.URL.Path, rec.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
