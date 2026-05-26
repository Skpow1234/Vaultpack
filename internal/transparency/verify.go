package transparency

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// VerifyParams bundles the inputs for VerifySET.
type VerifyParams struct {
	// RekorPubPEM is Rekor's PEM-encoded ECDSA P-256 public key.
	RekorPubPEM []byte
	// LogID is the canonical Rekor log ID (hex sha256 of the log's DER pub key).
	// May be empty when the verifier doesn't pin a log ID.
	LogID string
	// LogIndex / IntegratedTime are the values returned by Rekor.
	LogIndex       int64
	IntegratedTime int64
	// Body is the base64-encoded canonical entry body Rekor returned.
	Body string
	// SETB64 is the base64-encoded Signed Entry Timestamp signature.
	SETB64 string
}

// VerifySET checks Rekor's Signed Entry Timestamp signature against its public
// key. The canonicalization is the same one Rekor uses server-side: the SET
// covers the canonical JSON of {body, integratedTime, logID, logIndex} with
// alphabetic key ordering and no whitespace.
func VerifySET(params VerifyParams) error {
	if params.SETB64 == "" {
		return errors.New("empty SET")
	}
	sig, err := base64.StdEncoding.DecodeString(params.SETB64)
	if err != nil {
		return fmt.Errorf("decode SET: %w", err)
	}
	pub, err := parseRekorPublicKey(params.RekorPubPEM)
	if err != nil {
		return err
	}
	canonical, err := canonicalSETPayload(params.Body, params.IntegratedTime, params.LogID, params.LogIndex)
	if err != nil {
		return fmt.Errorf("canonicalize SET payload: %w", err)
	}
	sum := sha256.Sum256(canonical)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, sum[:], sig) {
			return errors.New("SET signature invalid (ecdsa)")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, canonical, sig) {
			return errors.New("SET signature invalid (ed25519)")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig); err != nil {
			return fmt.Errorf("SET signature invalid (rsa): %w", err)
		}
	default:
		return fmt.Errorf("unsupported Rekor key type %T", pub)
	}
	return nil
}

// canonicalSETPayload reproduces the bytes Rekor signs over. Rekor's canonical
// form is JSON of {body, integratedTime, logID, logIndex} with keys in
// alphabetical order and no extraneous whitespace.
func canonicalSETPayload(body string, integratedTime int64, logID string, logIndex int64) ([]byte, error) {
	// Match Rekor's ordering: body, integratedTime, logID, logIndex.
	type canon struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}
	return json.Marshal(canon{
		Body:           body,
		IntegratedTime: integratedTime,
		LogID:          logID,
		LogIndex:       logIndex,
	})
}

// parseRekorPublicKey decodes a PEM block (PUBLIC KEY) into a crypto.PublicKey.
func parseRekorPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("rekor pubkey: no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rekor pubkey: %w", err)
	}
	return pub, nil
}

// DecodeBody decodes a base64-encoded canonical entry body and unmarshals it
// into the supplied destination (typically a *HashedRekordEntry). It is
// provided so verifiers can re-extract the data hash and pubkey embedded in
// the Rekor record and cross-check them against the bundle.
func DecodeBody(b64 string, dst any) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	return json.Unmarshal(raw, dst)
}
