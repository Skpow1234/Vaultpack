package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	// EncryptionContextKey is the key used in AWS KMS encryption context for vaultpack DEK wrap.
	EncryptionContextKey = "vaultpack"
	// EncryptionContextValue is the value for the context key.
	EncryptionContextValue = "dek-wrap"
)

// AWSProvider wraps and unwraps DEKs using AWS KMS (symmetric CMK).
type AWSProvider struct {
	client *kms.Client
}

// NewAWSProvider creates an AWS KMS provider using default credential chain (env, shared config, IAM role).
func NewAWSProvider(ctx context.Context) (*AWSProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &AWSProvider{client: kms.NewFromConfig(cfg)}, nil
}

// WrapDEK encrypts the DEK with the AWS KMS key identified by keyID (e.g. alias/my-key or key ARN).
func (a *AWSProvider) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	ctx := context.Background()
	out, err := a.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             aws.String(keyID),
		Plaintext:         plainDEK,
		EncryptionContext: map[string]string{EncryptionContextKey: EncryptionContextValue},
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// UnwrapDEK decrypts the wrapped DEK. keyID is optional (AWS can deduce from ciphertext) but may be used for validation.
func (a *AWSProvider) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	ctx := context.Background()
	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:     wrapped,
		EncryptionContext: map[string]string{EncryptionContextKey: EncryptionContextValue},
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

func init() {
	// Lazy init: AWS provider is created on first use (requires AWS credentials).
	// Register a factory-style provider that builds the client when first used.
	Register("aws", &awsProviderLazy{})
}

// awsProviderLazy builds the real AWS client on first Wrap or Unwrap.
type awsProviderLazy struct {
	inner *AWSProvider
}

func (a *awsProviderLazy) WrapDEK(plainDEK []byte, keyID string) ([]byte, error) {
	p, err := a.get()
	if err != nil {
		return nil, err
	}
	return p.WrapDEK(plainDEK, keyID)
}

func (a *awsProviderLazy) UnwrapDEK(wrapped []byte, keyID string) ([]byte, error) {
	p, err := a.get()
	if err != nil {
		return nil, err
	}
	return p.UnwrapDEK(wrapped, keyID)
}

func (a *awsProviderLazy) get() (*AWSProvider, error) {
	if a.inner != nil {
		return a.inner, nil
	}
	p, err := NewAWSProvider(context.Background())
	if err != nil {
		return nil, err
	}
	a.inner = p
	return p, nil
}
