package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	azuremod "github.com/Skpow1234/Vaultpack/internal/azure"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// Azure configuration set via CLI flags or environment variables.
var (
	azureAccountName      string
	azureConnectionString string
)

// resolveAzureEnv fills empty config values from environment variables.
func resolveAzureEnv() {
	if azureAccountName == "" {
		azureAccountName = os.Getenv("AZURE_STORAGE_ACCOUNT")
	}
	if azureConnectionString == "" {
		azureConnectionString = os.Getenv("AZURE_STORAGE_CONNECTION_STRING")
	}
}

// getAzureClient returns an Azure Blob service client using the current config.
func getAzureClient() (*azblob.Client, error) {
	resolveAzureEnv()
	return azuremod.NewServiceClient(azuremod.ClientOptions{
		AccountName:      azureAccountName,
		ConnectionString: azureConnectionString,
	})
}

// isAzure returns true if the path is an az:// URI.
func isAzure(path string) bool {
	return azuremod.IsAzureURI(path)
}

// azureDownload downloads a blob to a local temp file and returns the temp file path.
// The caller is responsible for removing the temp file.
func azureDownload(uri string) (string, error) {
	containerName, blobPath, err := azuremod.ParseURI(uri)
	if err != nil {
		return "", err
	}

	client, err := getAzureClient()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	data, err := azuremod.DownloadBlob(ctx, client, containerName, blobPath)
	if err != nil {
		return "", err
	}

	// Write to a temp file with the original extension preserved.
	ext := filepath.Ext(blobPath)
	if ext == "" {
		ext = ".tmp"
	}
	tmpFile, err := os.CreateTemp("", "vaultpack-az-*"+ext)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()
	return tmpFile.Name(), nil
}

// azureUploadFile uploads a local file to an Azure blob.
func azureUploadFile(localPath, uri string) error {
	containerName, blobPath, err := azuremod.ParseURI(uri)
	if err != nil {
		return err
	}

	client, err := getAzureClient()
	if err != nil {
		return err
	}

	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat local file: %w", err)
	}

	ctx := context.Background()
	return azuremod.UploadBlob(ctx, client, containerName, blobPath, f, info.Size())
}

// azureUploadBytes uploads raw bytes to an Azure blob.
func azureUploadBytes(data []byte, uri string) error {
	containerName, blobPath, err := azuremod.ParseURI(uri)
	if err != nil {
		return err
	}

	client, err := getAzureClient()
	if err != nil {
		return err
	}

	ctx := context.Background()
	return azuremod.UploadBlob(ctx, client, containerName, blobPath, bytes.NewReader(data), int64(len(data)))
}

// azureListBlobs lists blobs under a prefix (directory-like listing).
func azureListBlobs(uri string) ([]string, error) {
	containerName, prefix, err := azuremod.ParseURI(uri)
	if err != nil {
		return nil, err
	}

	// Ensure prefix ends with "/" for directory-like listing.
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	client, err := getAzureClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	return azuremod.ListBlobs(ctx, client, containerName, prefix)
}

// azureDownloadDir downloads all blobs under a prefix to a local temp directory.
// Returns the temp directory path and a cleanup function.
func azureDownloadDir(uri string) (string, func(), error) {
	containerName, prefix, err := azuremod.ParseURI(uri)
	if err != nil {
		return "", nil, err
	}

	// Ensure prefix ends with "/".
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	client, err := getAzureClient()
	if err != nil {
		return "", nil, err
	}

	ctx := context.Background()
	blobNames, err := azuremod.ListBlobs(ctx, client, containerName, prefix)
	if err != nil {
		return "", nil, err
	}

	tmpDir, err := os.MkdirTemp("", "vaultpack-az-dir-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmpDir) }

	for _, blobName := range blobNames {
		// Strip the prefix to get the relative path.
		relPath := strings.TrimPrefix(blobName, prefix)
		if relPath == "" {
			continue
		}

		localPath := filepath.Join(tmpDir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("create dir for %s: %w", relPath, err)
		}

		data, err := azuremod.DownloadBlob(ctx, client, containerName, blobName)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("download %s: %w", blobName, err)
		}

		if err := os.WriteFile(localPath, data, 0o600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write %s: %w", localPath, err)
		}
	}

	return tmpDir, cleanup, nil
}

// azureUploadDir uploads all files in a local directory to an Azure blob prefix.
func azureUploadDir(localDir, uri string) error {
	containerName, prefix, err := azuremod.ParseURI(uri)
	if err != nil {
		return err
	}

	// Ensure prefix ends with "/".
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	client, err := getAzureClient()
	if err != nil {
		return err
	}

	ctx := context.Background()
	return filepath.Walk(localDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		blobPath := prefix + filepath.ToSlash(relPath)

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		return azuremod.UploadBlob(ctx, client, containerName, blobPath, f, info.Size())
	})
}

// azureDownloadToReader downloads a blob and returns an io.Reader over its contents.
func azureDownloadToReader(uri string) (io.Reader, int64, string, error) {
	containerName, blobPath, err := azuremod.ParseURI(uri)
	if err != nil {
		return nil, 0, "", err
	}

	client, err := getAzureClient()
	if err != nil {
		return nil, 0, "", err
	}

	ctx := context.Background()
	data, err := azuremod.DownloadBlob(ctx, client, containerName, blobPath)
	if err != nil {
		return nil, 0, "", err
	}

	name := filepath.Base(blobPath)
	return bytes.NewReader(data), int64(len(data)), name, nil
}
