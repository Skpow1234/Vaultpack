package kms

import (
	"context"

	kmsapi "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// GCP AAD for DEK wrap (optional authenticated context).
var gcpAAD = []byte("vaultpack-dek-wrap")

// GCPProvider wraps and unwraps DEKs using GCP Cloud KMS (symmetric CryptoKey).
// keyID must be the full resource name: projects/PROJECT_ID/locations/LOCATION/keyRings/RING/cryptoKeys/KEY_NAME.
type GCPProvider struct {
	client *kmsapi.KeyManagementClient
}

// NewGCPProvider creates a GCP KMS provider using Application Default Credentials (ADC).
func NewGCPProvider(ctx context.Context) (*GCPProvider, error) {
	client, err := kmsapi.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return &GCPProvider{client: client}, nil
}

// WrapDEK encrypts the DEK with the GCP KMS key identified by keyID (full resource name).
func (g *GCPProvider) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	ctx := context.Background()
	resp, err := g.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        keyID,
		Plaintext:                   plainDEK,
		AdditionalAuthenticatedData: gcpAAD,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

// UnwrapDEK decrypts the wrapped DEK. keyID must match the key used for encryption.
func (g *GCPProvider) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	ctx := context.Background()
	resp, err := g.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        keyID,
		Ciphertext:                  wrapped,
		AdditionalAuthenticatedData: gcpAAD,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func init() {
	Register("gcp", &gcpProviderLazy{})
}

type gcpProviderLazy struct {
	inner *GCPProvider
}

func (g *gcpProviderLazy) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	p, err := g.get()
	if err != nil {
		return nil, err
	}
	return p.WrapDEK(plainDEK, keyID)
}

func (g *gcpProviderLazy) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	p, err := g.get()
	if err != nil {
		return nil, err
	}
	return p.UnwrapDEK(wrapped, keyID)
}

func (g *gcpProviderLazy) get() (*GCPProvider, error) {
	if g.inner != nil {
		return g.inner, nil
	}
	p, err := NewGCPProvider(context.Background())
	if err != nil {
		return nil, err
	}
	g.inner = p
	return p, nil
}
