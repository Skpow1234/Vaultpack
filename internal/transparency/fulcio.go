package transparency

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FulcioClient is a minimal client for the Sigstore Fulcio CA. It implements
// the single endpoint VaultPack needs: POST /api/v2/signingCert to exchange an
// OIDC token + CSR / PEM proof for a short-lived signing certificate.
type FulcioClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewFulcioClient targets baseURL (defaults to the public Fulcio instance).
func NewFulcioClient(baseURL string) *FulcioClient {
	if baseURL == "" {
		baseURL = DefaultFulcioURL
	}
	return &FulcioClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// SigningCertRequest is Fulcio v2's `signingCert` request payload. It uses the
// publicKeyRequest variant (raw public key + a signature proving possession of
// the matching private key).
type SigningCertRequest struct {
	PublicKeyRequest PublicKeyRequest `json:"publicKeyRequest"`
}

// PublicKeyRequest tells Fulcio which key to certify and proves possession of
// the matching private key by signing the OIDC subject.
type PublicKeyRequest struct {
	PublicKey               PublicKey `json:"publicKey"`
	ProofOfPossession       string    `json:"proofOfPossession"` // base64(sig over subject email/SAN)
}

type PublicKey struct {
	Algorithm string `json:"algorithm"` // "ECDSA" | "ED25519" | "RSA_PSS"
	Content   string `json:"content"`   // PEM-encoded PUBLIC KEY
}

// SigningCertResponse is Fulcio v2's response. signedCertificateEmbeddedSct or
// signedCertificateDetachedSct is set, never both; either way we just take the
// chain PEMs verbatim.
type SigningCertResponse struct {
	SignedCertificateEmbeddedSct *SignedCertificate `json:"signedCertificateEmbeddedSct,omitempty"`
	SignedCertificateDetachedSct *SignedCertificate `json:"signedCertificateDetachedSct,omitempty"`
}

type SignedCertificate struct {
	Chain                  Chain  `json:"chain"`
	SignedCertificateTimestamp string `json:"signedCertificateTimestamp,omitempty"`
}

type Chain struct {
	Certificates []string `json:"certificates"` // PEM-encoded leaf + intermediates
}

// GetSigningCert exchanges an OIDC ID token + ECDSA public key + proof-of-
// possession signature for a short-lived signing certificate.
//
// The caller must:
//   1. Hold an ECDSA P-256 keypair (Fulcio currently restricts the public
//      keys it certifies; we use ECDSA here for the broadest compatibility).
//   2. Have signed the OIDC token's subject (email or SAN) with that key and
//      base64-encoded the result into proofOfPossessionB64.
func (c *FulcioClient) GetSigningCert(ctx context.Context, oidcToken string, pubKey *ecdsa.PublicKey, proofOfPossessionB64 string) (chainPEM string, err error) {
	if oidcToken == "" {
		return "", errors.New("oidc token is empty")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	req := SigningCertRequest{
		PublicKeyRequest: PublicKeyRequest{
			PublicKey: PublicKey{
				Algorithm: "ECDSA",
				Content:   string(pubPEM),
			},
			ProofOfPossession: proofOfPossessionB64,
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v2/signingCert", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+oidcToken)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("post signingCert: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fulcio: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out SigningCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	sc := out.SignedCertificateEmbeddedSct
	if sc == nil {
		sc = out.SignedCertificateDetachedSct
	}
	if sc == nil || len(sc.Chain.Certificates) == 0 {
		return "", errors.New("fulcio: empty cert chain")
	}
	return strings.Join(sc.Chain.Certificates, ""), nil
}
