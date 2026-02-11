// Package azure provides Azure Blob Storage I/O for VaultPack.
//
// URI scheme:
//
//	az://container/path/to/blob
//
// Account is resolved from:
//  1. --azure-account flag (stored in AzureAccountName env)
//  2. AZURE_STORAGE_ACCOUNT env var
//
// Auth order:
//  1. AZURE_STORAGE_CONNECTION_STRING env var (or --azure-connection-string flag)
//  2. azidentity.DefaultAzureCredential (managed identity → env vars → Azure CLI)
package azure

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// IsAzureURI returns true if the path starts with "az://".
func IsAzureURI(path string) bool {
	return strings.HasPrefix(path, "az://")
}

// ParseURI splits an "az://container/blob/path" into container name and blob path.
// Returns an error if the URI is malformed.
func ParseURI(uri string) (containerName, blobPath string, err error) {
	if !IsAzureURI(uri) {
		return "", "", fmt.Errorf("not an Azure URI: %q", uri)
	}
	rest := strings.TrimPrefix(uri, "az://")
	if rest == "" {
		return "", "", fmt.Errorf("empty Azure URI")
	}

	// Split on first '/'.
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		// Container only, no blob path.
		return rest, "", nil
	}
	containerName = rest[:idx]
	blobPath = rest[idx+1:]
	if containerName == "" {
		return "", "", fmt.Errorf("empty container name in URI %q", uri)
	}
	return containerName, blobPath, nil
}

// ClientOptions holds options for building an Azure Blob client.
type ClientOptions struct {
	AccountName      string // Azure storage account name
	ConnectionString string // optional; takes precedence over DefaultAzureCredential
}

// NewServiceClient creates a *azblob.Client for the given options.
// If ConnectionString is set, it is used. Otherwise DefaultAzureCredential
// is created and the service URL is derived from AccountName.
func NewServiceClient(opts ClientOptions) (*azblob.Client, error) {
	if opts.ConnectionString != "" {
		client, err := azblob.NewClientFromConnectionString(opts.ConnectionString, nil)
		if err != nil {
			return nil, fmt.Errorf("azure connection string: %w", err)
		}
		return client, nil
	}

	if opts.AccountName == "" {
		return nil, fmt.Errorf("AZURE_STORAGE_ACCOUNT (or --azure-account) is required when not using a connection string")
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", opts.AccountName)

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure default credential: %w", err)
	}

	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure client: %w", err)
	}
	return client, nil
}

// DownloadBlob downloads a blob and returns its content as a byte slice.
func DownloadBlob(ctx context.Context, client *azblob.Client, containerName, blobPath string) ([]byte, error) {
	resp, err := client.DownloadStream(ctx, containerName, blobPath, nil)
	if err != nil {
		return nil, fmt.Errorf("azure download %s/%s: %w", containerName, blobPath, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("azure read stream %s/%s: %w", containerName, blobPath, err)
	}
	return data, nil
}

// DownloadBlobToWriter streams a blob download into the given writer.
func DownloadBlobToWriter(ctx context.Context, client *azblob.Client, containerName, blobPath string, w io.Writer) error {
	resp, err := client.DownloadStream(ctx, containerName, blobPath, nil)
	if err != nil {
		return fmt.Errorf("azure download %s/%s: %w", containerName, blobPath, err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("azure read stream %s/%s: %w", containerName, blobPath, err)
	}
	return nil
}

// UploadBlob uploads data from an io.Reader to an Azure blob using streaming upload.
func UploadBlob(ctx context.Context, client *azblob.Client, containerName, blobPath string, r io.Reader, size int64) error {
	_, err := client.UploadStream(ctx, containerName, blobPath, r, &blockblob.UploadStreamOptions{
		// Use 4 MiB blocks, 3 concurrent uploads by default (SDK defaults are reasonable).
	})
	if err != nil {
		return fmt.Errorf("azure upload %s/%s: %w", containerName, blobPath, err)
	}
	return nil
}

// UploadBlobBytes uploads a byte slice to an Azure blob.
func UploadBlobBytes(ctx context.Context, client *azblob.Client, containerName, blobPath string, data []byte) error {
	return UploadBlob(ctx, client, containerName, blobPath, strings.NewReader(string(data)), int64(len(data)))
}

// ListBlobs lists all blobs under a prefix within a container.
// The prefix should end with "/" for directory-like behavior.
func ListBlobs(ctx context.Context, client *azblob.Client, containerName, prefix string) ([]string, error) {
	var blobs []string

	pager := client.NewListBlobsFlatPager(containerName, &container.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure list blobs %s/%s: %w", containerName, prefix, err)
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name != nil {
				blobs = append(blobs, *item.Name)
			}
		}
	}

	return blobs, nil
}
