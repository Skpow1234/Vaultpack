package kms

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

var errInvalidAzureKeyID = errors.New("invalid Azure key ID: expected https://<vault>.vault.azure.net/keys/<key-name>/[version]")

// AzureProvider wraps and unwraps DEKs using Azure Key Vault (RSA-OAEP-256 wrap/unwrap).
// keyID must be the full key identifier: https://<vault-name>.vault.azure.net/keys/<key-name>[/<version>].
// If version is omitted, the default (latest) version is used.
type AzureProvider struct {
	client *azkeys.Client
}

// ParseAzureKeyID returns (vaultURL, keyName, version) from an Azure key identifier URL.
// keyID format: https://<vault>.vault.azure.net/keys/<keyname>/<version> or .../keys/<keyname>.
func ParseAzureKeyID(keyID string) (vaultURL, keyName, version string, err error) {
	u, err := url.Parse(keyID)
	if err != nil {
		return "", "", "", errInvalidAzureKeyID
	}
	if u.Scheme != "https" || !strings.HasSuffix(u.Host, ".vault.azure.net") {
		return "", "", "", errInvalidAzureKeyID
	}
	path := strings.TrimPrefix(u.Path, "/")
	parts := strings.SplitN(path, "/", 3) // keys / keyname / [version]
	if len(parts) < 2 || parts[0] != "keys" {
		return "", "", "", errInvalidAzureKeyID
	}
	keyName = parts[1]
	version = ""
	if len(parts) >= 3 {
		version = parts[2]
	}
	vaultURL = "https://" + u.Host
	return vaultURL, keyName, version, nil
}

// NewAzureProvider creates an Azure Key Vault provider for the given vault URL (e.g. https://myvault.vault.azure.net).
// Uses DefaultAzureCredential (managed identity, env, Azure CLI, etc.).
func NewAzureProvider(ctx context.Context, vaultURL string) (*AzureProvider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}
	return &AzureProvider{client: client}, nil
}

// WrapDEK wraps the DEK using the key identified by keyID (full Azure key URL). Uses RSA-OAEP-256.
func (a *AzureProvider) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	_, keyName, version, err := ParseAzureKeyID(keyID)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := a.client.WrapKey(ctx, keyName, version, azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     plainDEK,
	}, nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

// UnwrapDEK unwraps the DEK. keyID must be the same key URL used for wrapping.
func (a *AzureProvider) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	_, keyName, version, err := ParseAzureKeyID(keyID)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := a.client.UnwrapKey(ctx, keyName, version, azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     wrapped,
	}, nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func init() {
	Register("azure", &azureProviderLazy{})
}

// azureProviderLazy creates a client on first use; keyID (full URL) determines the vault.
type azureProviderLazy struct {
	inner *AzureProvider
}

func (a *azureProviderLazy) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	p, err := a.get(keyID)
	if err != nil {
		return nil, err
	}
	return p.WrapDEK(plainDEK, keyID)
}

func (a *azureProviderLazy) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	p, err := a.get(keyID)
	if err != nil {
		return nil, err
	}
	return p.UnwrapDEK(wrapped, keyID)
}

func (a *azureProviderLazy) get(keyID string) (*AzureProvider, error) {
	vaultURL, _, _, err := ParseAzureKeyID(keyID)
	if err != nil {
		return nil, err
	}
	// Reuse same client if same vault (simple: always create new for now to avoid caching by vault).
	p, err := NewAzureProvider(context.Background(), vaultURL)
	if err != nil {
		return nil, err
	}
	return p, nil
}
