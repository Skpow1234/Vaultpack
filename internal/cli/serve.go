package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/serve"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var (
		listen          string
		tlsCert         string
		tlsKey          string
		tlsClientCA     string
		authToken       string
		authTokenFile   string
		authDisabled    bool
		kmsCacheTTL     time.Duration
		kmsCacheSize    int
		readTimeout     time.Duration
		writeTimeout    time.Duration
		maxRequestBytes int64
		policyFile      string
		auditLogFile    string
		rateLimitRPS    float64
		rateLimitBurst  int
		oidcIssuer      string
		oidcAudience    string
		oidcJWKSURL     string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the VaultPack HTTP API server",
		Long: `Run a long-running HTTP API exposing the VaultPack SDK to remote
clients. The wire contract matches the C-shared library and WASM
bindings: JSON in, JSON out, {ok: true|false} envelope.

Endpoints (all under /v1):
  GET  /v1/version       SDK + API version
  POST /v1/protect       Encrypt → bundle
  POST /v1/decrypt       Decrypt bundle
  POST /v1/inspect       Decode manifest
  POST /v1/sign          Add/replace detached signature
  POST /v1/verify        Verify detached signature
  POST /v1/rewrap        Re-wrap KMS DEK (rotation)

Operational endpoints (always reachable, no auth):
  GET  /healthz          Liveness probe
  GET  /metrics          Prometheus exposition

Authentication: provide --auth-token, --tls-client-ca (mTLS), OIDC JWT
(--oidc-issuer + --oidc-audience), or both. Pass --auth-disabled only for
local development; the server otherwise refuses to start without any auth.

Policy and audit: pass --policy and --audit-log to enforce the same RBAC
rules and tamper-evident logging as the CLI on every /v1/* call.

Examples:
  vaultpack serve --listen :8443 --auth-token "$(cat token.txt)" \
                  --tls-cert server.crt --tls-key server.key
  vaultpack serve --listen unix:/run/vaultpack.sock --auth-disabled`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if authToken == "" && authTokenFile != "" {
				b, err := os.ReadFile(authTokenFile)
				if err != nil {
					return fmt.Errorf("read --auth-token-file: %w", err)
				}
				authToken = string(b)
				// Trim trailing newline that most editors append.
				for len(authToken) > 0 && (authToken[len(authToken)-1] == '\n' || authToken[len(authToken)-1] == '\r') {
					authToken = authToken[:len(authToken)-1]
				}
			}

			srv, err := serve.NewServer(serve.Options{
				Listen:          listen,
				TLSCertFile:     tlsCert,
				TLSKeyFile:      tlsKey,
				TLSClientCAFile: tlsClientCA,
				AuthToken:       authToken,
				AuthDisabled:    authDisabled,
				KMSCacheTTL:     kmsCacheTTL,
				KMSCacheMaxSize: kmsCacheSize,
				ReadTimeout:     readTimeout,
				WriteTimeout:    writeTimeout,
				MaxRequestBytes: maxRequestBytes,
				PolicyFile:      policyFile,
				AuditLogFile:    auditLogFile,
				RateLimitRPS:    rateLimitRPS,
				RateLimitBurst:  rateLimitBurst,
				OIDC: serve.OIDCOptions{
					Issuer:   oidcIssuer,
					Audience: oidcAudience,
					JWKSURL:  oidcJWKSURL,
				},
			})
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			printer := NewPrinter(flagJSON, flagQuiet)
			printer.Human("vaultpack serve: listening on %s (TLS=%v, mTLS=%v, auth-token=%v)",
				listen,
				tlsCert != "",
				tlsClientCA != "",
				authToken != "",
			)
			if err := srv.ListenAndServe(ctx); err != nil {
				return fmt.Errorf("serve: %w", err)
			}
			printer.Human("vaultpack serve: shut down cleanly")
			return nil
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8443", "Listen address (\"host:port\" or \"unix:/path/socket\")")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS server certificate (PEM)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS server private key (PEM)")
	cmd.Flags().StringVar(&tlsClientCA, "tls-client-ca", "", "Path to PEM bundle of trusted client CAs (enables mTLS)")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Require Authorization: Bearer <token> on every request")
	cmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "Read --auth-token from this file (trailing newline stripped)")
	cmd.Flags().BoolVar(&authDisabled, "auth-disabled", false, "Explicit opt-out: serve without any authentication (LOCAL DEV ONLY)")
	cmd.Flags().DurationVar(&kmsCacheTTL, "kms-cache-ttl", 5*time.Minute, "TTL for cached KMS unwrap results")
	cmd.Flags().IntVar(&kmsCacheSize, "kms-cache-size", 1024, "Max entries in the KMS unwrap cache")
	cmd.Flags().DurationVar(&readTimeout, "read-timeout", 30*time.Second, "HTTP read timeout")
	cmd.Flags().DurationVar(&writeTimeout, "write-timeout", 30*time.Second, "HTTP write timeout")
	cmd.Flags().Int64Var(&maxRequestBytes, "max-request-bytes", 64<<20, "Maximum request body size in bytes")
	cmd.Flags().StringVar(&policyFile, "policy", "", "Policy file (YAML/JSON/Rego) enforced on every /v1/* call")
	cmd.Flags().StringVar(&auditLogFile, "audit-log", "", "Append-only audit log file for /v1/* operations")
	cmd.Flags().Float64Var(&rateLimitRPS, "rate-limit-rps", 0, "Per-IP request rate limit (requests/sec; 0 = disabled)")
	cmd.Flags().IntVar(&rateLimitBurst, "rate-limit-burst", 0, "Rate limit burst size (default: rps+1)")
	cmd.Flags().StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL for JWT bearer auth")
	cmd.Flags().StringVar(&oidcAudience, "oidc-audience", "", "Expected JWT audience claim for OIDC auth")
	cmd.Flags().StringVar(&oidcJWKSURL, "oidc-jwks-url", "", "JWKS URL (optional; derived from issuer when empty)")

	return cmd
}
