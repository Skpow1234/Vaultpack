// Package httpfetch provides a read-only cloud.Store implementation that
// downloads bundles over HTTPS (or HTTP for testing).
//
// URI scheme:
//
//	https://host/path
//	http://host/path
//
// Authentication is supported via:
//   - VAULTPACK_HTTP_BEARER environment variable (sent as Authorization: Bearer ...).
//   - VAULTPACK_HTTP_USER + VAULTPACK_HTTP_PASS for HTTP Basic auth.
//
// Uploads are not supported; Upload returns cloud.ErrReadOnly.
// List is not supported; List returns cloud.ErrNotSupported.
package httpfetch

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
)

// Store implements cloud.Store by fetching objects over HTTP(S).
type Store struct {
	client *http.Client
}

// Options configures the HTTPS store.
type Options struct {
	// Timeout for individual requests; 0 uses the default (5 minutes).
	Timeout time.Duration
}

// NewStore constructs an HTTPS Store.
func NewStore(opts Options) *Store {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return &Store{client: &http.Client{Timeout: timeout}}
}

// Scheme returns "https".
func (s *Store) Scheme() cloud.Scheme { return cloud.SchemeHTTPS }

func (s *Store) newRequest(ctx context.Context, uri string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	if tok := os.Getenv("VAULTPACK_HTTP_BEARER"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if u, p := os.Getenv("VAULTPACK_HTTP_USER"), os.Getenv("VAULTPACK_HTTP_PASS"); u != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	req.Header.Set("User-Agent", "vaultpack/m21")
	return req, nil
}

// Download performs an HTTPS GET and returns the response body.
func (s *Store) Download(ctx context.Context, uri string) ([]byte, error) {
	req, err := s.newRequest(ctx, uri)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get %s: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("http get %s: status %d", uri, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("http read %s: %w", uri, err)
	}
	return data, nil
}

// DownloadToWriter streams the response body into w.
func (s *Store) DownloadToWriter(ctx context.Context, uri string, w io.Writer) error {
	req, err := s.newRequest(ctx, uri)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http get %s: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("http get %s: status %d", uri, resp.StatusCode)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("http stream %s: %w", uri, err)
	}
	return nil
}

// Upload is not supported on HTTPS; returns cloud.ErrReadOnly.
func (s *Store) Upload(ctx context.Context, uri string, r io.Reader, size int64) error {
	return cloud.ErrReadOnly
}

// List is not supported on HTTPS; returns cloud.ErrNotSupported.
func (s *Store) List(ctx context.Context, prefixURI string) ([]string, error) {
	return nil, cloud.ErrNotSupported
}

var _ cloud.Store = (*Store)(nil)
