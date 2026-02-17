package kms

import "fmt"

// Provider wraps and unwraps a DEK using a KMS (e.g. AWS KMS, GCP Cloud KMS, Azure Key Vault).
// The DEK is never persisted in plaintext; only the KMS-wrapped ciphertext and key ID are stored.
type Provider interface {
	// WrapDEK encrypts the plain DEK with the KMS key identified by keyID. Returns the ciphertext to store in the manifest.
	WrapDEK(plainDEK []byte, keyID string) (wrapped []byte, err error)
	// UnwrapDEK decrypts the wrapped DEK using the same KMS key identified by keyID.
	UnwrapDEK(wrapped []byte, keyID string) ([]byte, error)
}

// Registry holds named KMS providers (e.g. "aws", "mock").
var registry = make(map[string]Provider)

// Register adds a provider under the given name. Panics if name is empty or already registered.
func Register(name string, p Provider) {
	if name == "" {
		panic("kms: empty provider name")
	}
	if _, ok := registry[name]; ok {
		panic("kms: provider " + name + " already registered")
	}
	registry[name] = p
}

// Get returns the provider for the given name, or nil if not found.
func Get(name string) Provider {
	return registry[name]
}

// Providers returns the list of registered provider names.
func Providers() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}

// ErrProviderNotFound is returned when the requested KMS provider is not registered.
var ErrProviderNotFound = fmt.Errorf("kms provider not found")
