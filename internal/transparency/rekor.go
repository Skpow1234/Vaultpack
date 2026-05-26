package transparency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RekorClient is a minimal client for the Rekor REST API. It only implements
// the surface VaultPack needs: hashedrekord upload, entry fetch by UUID, and
// public-key retrieval (used to verify SETs).
type RekorClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewRekorClient returns a client targeting baseURL (defaults to public Rekor).
func NewRekorClient(baseURL string) *RekorClient {
	if baseURL == "" {
		baseURL = DefaultRekorURL
	}
	return &RekorClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// BuildHashedRekord constructs a hashedrekord-v0.0.1 entry suitable for upload.
//
// pubKeyPEMOrCert may be either a PEM-encoded public key OR a PEM-encoded cert
// chain (Fulcio leaf+chain). signature is the raw signature bytes.
// data is the bytes that were signed (Rekor will hash them with SHA-256
// server-side and compare with the supplied hash).
func BuildHashedRekord(pubKeyPEMOrCert, signature, data []byte) HashedRekordEntry {
	sum := sha256.Sum256(data)
	return HashedRekordEntry{
		APIVersion: APIVersionV001,
		Kind:       KindHashedRekord,
		Spec: HashedRekordEntrySpec{
			Signature: HashedRekordSignature{
				Content: base64.StdEncoding.EncodeToString(signature),
				PublicKey: HashedRekordPublicKey{
					Content: base64.StdEncoding.EncodeToString(pubKeyPEMOrCert),
				},
			},
			Data: HashedRekordData{
				Hash: HashedRekordHash{
					Algorithm: "sha256",
					Value:     hex.EncodeToString(sum[:]),
				},
			},
		},
	}
}

// Upload POSTs an entry to /api/v1/log/entries and returns the UUID and parsed
// LogEntryAnon. Rekor enforces uniqueness on (kind, signature, data); duplicate
// uploads return 409 with a Location header pointing at the existing UUID,
// which we transparently follow.
func (c *RekorClient) Upload(ctx context.Context, entry HashedRekordEntry) (uuid string, anon LogEntryAnon, err error) {
	body, err := json.Marshal(entry)
	if err != nil {
		return "", LogEntryAnon{}, fmt.Errorf("marshal entry: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return "", LogEntryAnon{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", LogEntryAnon{}, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// fall through
	case http.StatusConflict:
		// Rekor returns Location: /api/v1/log/entries/<uuid> for duplicates.
		loc := resp.Header.Get("Location")
		if loc == "" {
			return "", LogEntryAnon{}, fmt.Errorf("rekor: 409 with no Location header")
		}
		parts := strings.Split(strings.TrimPrefix(loc, "/api/v1/log/entries/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			return "", LogEntryAnon{}, fmt.Errorf("rekor: malformed Location: %s", loc)
		}
		uuid = parts[0]
		anon, err = c.Fetch(ctx, uuid)
		return uuid, anon, err
	default:
		raw, _ := io.ReadAll(resp.Body)
		return "", LogEntryAnon{}, fmt.Errorf("rekor upload: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}

	uuid, anon, err = parseEntryResponse(resp.Body)
	return uuid, anon, err
}

// Fetch returns the LogEntryAnon stored under UUID.
func (c *RekorClient) Fetch(ctx context.Context, uuid string) (LogEntryAnon, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries/%s", c.BaseURL, uuid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return LogEntryAnon{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return LogEntryAnon{}, fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return LogEntryAnon{}, fmt.Errorf("rekor fetch: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	_, anon, err := parseEntryResponse(resp.Body)
	return anon, err
}

// PublicKey fetches Rekor's PEM-encoded ECDSA public key. Verifiers cache
// this once and use it to validate SETs.
func (c *RekorClient) PublicKey(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/log/publicKey", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get pubkey: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rekor pubkey: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	return io.ReadAll(resp.Body)
}

// parseEntryResponse reads Rekor's typical response shape: a single-key map
// keyed by the new entry's UUID.
func parseEntryResponse(body io.Reader) (string, LogEntryAnon, error) {
	var entries map[string]LogEntryAnon
	if err := json.NewDecoder(body).Decode(&entries); err != nil {
		return "", LogEntryAnon{}, fmt.Errorf("decode response: %w", err)
	}
	if len(entries) != 1 {
		return "", LogEntryAnon{}, fmt.Errorf("unexpected entries count: %d", len(entries))
	}
	for uuid, anon := range entries {
		return uuid, anon, nil
	}
	return "", LogEntryAnon{}, fmt.Errorf("unreachable")
}
