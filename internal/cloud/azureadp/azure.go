// Package azureadp adapts the existing internal/azure package to the
// cloud.Store interface so it can be plumbed through the generic
// remote-I/O helpers used by VaultPack's CLI.
package azureadp

import (
	"bytes"
	"context"
	"io"

	azuremod "github.com/Skpow1234/Vaultpack/internal/azure"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
)

// Store implements cloud.Store on top of internal/azure.
type Store struct {
	client *azblob.Client
}

// Options mirrors azuremod.ClientOptions.
type Options struct {
	AccountName      string
	ConnectionString string
}

// NewStore constructs an Azure cloud.Store.
func NewStore(opts Options) (*Store, error) {
	client, err := azuremod.NewServiceClient(azuremod.ClientOptions{
		AccountName:      opts.AccountName,
		ConnectionString: opts.ConnectionString,
	})
	if err != nil {
		return nil, err
	}
	return &Store{client: client}, nil
}

func (s *Store) Scheme() cloud.Scheme { return cloud.SchemeAzure }

func (s *Store) Download(ctx context.Context, uri string) ([]byte, error) {
	container, blob, err := azuremod.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return azuremod.DownloadBlob(ctx, s.client, container, blob)
}

func (s *Store) DownloadToWriter(ctx context.Context, uri string, w io.Writer) error {
	container, blob, err := azuremod.ParseURI(uri)
	if err != nil {
		return err
	}
	return azuremod.DownloadBlobToWriter(ctx, s.client, container, blob, w)
}

func (s *Store) Upload(ctx context.Context, uri string, r io.Reader, size int64) error {
	container, blob, err := azuremod.ParseURI(uri)
	if err != nil {
		return err
	}
	// internal/azure's UploadBlob streams from an io.Reader.
	if size < 0 {
		// Fall back to buffering when size is unknown.
		buf, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		return azuremod.UploadBlob(ctx, s.client, container, blob, bytes.NewReader(buf), int64(len(buf)))
	}
	return azuremod.UploadBlob(ctx, s.client, container, blob, r, size)
}

func (s *Store) List(ctx context.Context, prefixURI string) ([]string, error) {
	container, prefix, err := azuremod.ParseURI(prefixURI)
	if err != nil {
		return nil, err
	}
	return azuremod.ListBlobs(ctx, s.client, container, prefix)
}

var _ cloud.Store = (*Store)(nil)
