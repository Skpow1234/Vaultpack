package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/transparency"
)

// keylessSession is what `sign --keyless` produces: an ephemeral ECDSA
// signing key plus the Fulcio-issued cert chain that binds it to an OIDC
// identity. The caller signs the bundle with `Signer`, then uploads the
// signature + ChainPEM to Rekor via uploadToRekor.
type keylessSession struct {
	Signer   *ecdsa.PrivateKey
	ChainPEM string
	Identity string
	Issuer   string
}

// startKeylessSession runs the OIDC → Fulcio exchange. The OIDC token is read
// from oidcTokenFile (or env). An ephemeral P-256 ECDSA keypair is generated
// in-memory and never touches disk; the proof-of-possession signature is over
// the email/subject claim from the JWT.
func startKeylessSession(ctx context.Context, fulcioURL, oidcTokenFile string) (*keylessSession, error) {
	token, err := transparency.LoadOIDCToken(oidcTokenFile)
	if err != nil {
		return nil, err
	}
	claims, err := transparency.ParseOIDCClaims(token)
	if err != nil {
		return nil, fmt.Errorf("parse oidc token: %w", err)
	}
	subject := transparency.SubjectFromClaims(claims)
	if subject == "" {
		return nil, fmt.Errorf("oidc token has no email / sub / uri claim")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	// Proof-of-possession: ECDSA(P256) over SHA-256(subject).
	sum := sha256.Sum256([]byte(subject))
	popSig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		return nil, fmt.Errorf("sign pop: %w", err)
	}
	popB64 := base64.StdEncoding.EncodeToString(popSig)

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := transparency.NewFulcioClient(fulcioURL)
	chain, err := client.GetSigningCert(cctx, token, &priv.PublicKey, popB64)
	if err != nil {
		return nil, fmt.Errorf("fulcio: %w", err)
	}
	return &keylessSession{
		Signer:   priv,
		ChainPEM: chain,
		Identity: subject,
		Issuer:   claims.Issuer,
	}, nil
}
