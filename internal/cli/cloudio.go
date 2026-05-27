package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
	"github.com/Skpow1234/Vaultpack/internal/cloud/azureadp"
	"github.com/Skpow1234/Vaultpack/internal/cloud/gcs"
	"github.com/Skpow1234/Vaultpack/internal/cloud/httpfetch"
	s3store "github.com/Skpow1234/Vaultpack/internal/cloud/s3"
)

// Provider config set via CLI flags or environment variables.
var (
	awsRegion      string
	awsProfile     string
	awsS3Endpoint  string
	awsS3PathStyle bool
)

// isRemoteURI returns true if path is any supported remote URI (az/s3/gs/https).
func isRemoteURI(path string) bool { return cloud.IsRemote(path) }

// resolveAwsEnv fills empty AWS config from environment variables.
func resolveAwsEnv() {
	if awsRegion == "" {
		awsRegion = os.Getenv("AWS_REGION")
		if awsRegion == "" {
			awsRegion = os.Getenv("AWS_DEFAULT_REGION")
		}
	}
	if awsProfile == "" {
		awsProfile = os.Getenv("AWS_PROFILE")
	}
	if awsS3Endpoint == "" {
		awsS3Endpoint = os.Getenv("AWS_S3_ENDPOINT_URL")
	}
}

// storeFor returns a cloud.Store for the given URI's scheme.
func storeFor(ctx context.Context, uri string) (cloud.Store, error) {
	switch cloud.DetectScheme(uri) {
	case cloud.SchemeAzure:
		resolveAzureEnv()
		return azureadp.NewStore(azureadp.Options{
			AccountName:      azureAccountName,
			ConnectionString: azureConnectionString,
		})
	case cloud.SchemeS3:
		resolveAwsEnv()
		return s3store.NewStore(ctx, s3store.Options{
			Region:       awsRegion,
			Profile:      awsProfile,
			Endpoint:     awsS3Endpoint,
			UsePathStyle: awsS3PathStyle,
		})
	case cloud.SchemeGCS:
		return gcs.NewStore(ctx, gcs.Options{})
	case cloud.SchemeHTTPS, cloud.SchemeHTTP:
		return httpfetch.NewStore(httpfetch.Options{}), nil
	default:
		return nil, fmt.Errorf("unsupported URI scheme for %q", uri)
	}
}

// remoteDownload downloads a remote URI to a local temp file and returns the path.
// The caller must remove the temp file.
func remoteDownload(uri string) (string, error) {
	ctx := context.Background()
	store, err := storeFor(ctx, uri)
	if err != nil {
		return "", err
	}
	ext := filepath.Ext(uri)
	if ext == "" {
		ext = ".tmp"
	}
	tmp, err := os.CreateTemp("", "vaultpack-remote-*"+ext)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tmp.Close()
	if err := store.DownloadToWriter(ctx, uri, tmp); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// remoteUploadFile uploads a local file to the remote URI.
func remoteUploadFile(localPath, uri string) error {
	ctx := context.Background()
	if !cloud.IsWritable(uri) {
		return fmt.Errorf("scheme is read-only: %q", uri)
	}
	store, err := storeFor(ctx, uri)
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
	return store.Upload(ctx, uri, f, info.Size())
}

// remoteUploadBytes uploads raw bytes to a remote URI.
func remoteUploadBytes(data []byte, uri string) error {
	ctx := context.Background()
	if !cloud.IsWritable(uri) {
		return fmt.Errorf("scheme is read-only: %q", uri)
	}
	store, err := storeFor(ctx, uri)
	if err != nil {
		return err
	}
	return store.Upload(ctx, uri, bytes.NewReader(data), int64(len(data)))
}

// remoteList lists object keys under a remote prefix URI.
func remoteList(uri string) ([]string, error) {
	ctx := context.Background()
	store, err := storeFor(ctx, uri)
	if err != nil {
		return nil, err
	}
	return store.List(ctx, uri)
}

// remoteDownloadDir downloads all objects under a remote prefix URI to a temp dir.
// Returns the directory path and a cleanup function.
func remoteDownloadDir(uri string) (string, func(), error) {
	ctx := context.Background()
	store, err := storeFor(ctx, uri)
	if err != nil {
		return "", nil, err
	}

	// Normalize the URI to end with "/" so listing is prefix-based.
	listURI := uri
	if !strings.HasSuffix(listURI, "/") {
		listURI += "/"
	}
	names, err := store.List(ctx, listURI)
	if err != nil {
		return "", nil, err
	}

	tmpDir, err := os.MkdirTemp("", "vaultpack-remote-dir-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmpDir) }

	// Compute the prefix we used so we can strip it for relative paths.
	_, prefix, err := cloud.ParseBucketKey(listURI)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	for _, name := range names {
		rel := strings.TrimPrefix(name, prefix)
		if rel == "" {
			continue
		}
		localPath := filepath.Join(tmpDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("create dir for %s: %w", rel, err)
		}
		objURI := strings.TrimSuffix(listURI, prefix) + name
		f, err := os.Create(localPath)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("create %s: %w", localPath, err)
		}
		if err := store.DownloadToWriter(ctx, objURI, f); err != nil {
			f.Close()
			cleanup()
			return "", nil, fmt.Errorf("download %s: %w", objURI, err)
		}
		f.Close()
	}
	return tmpDir, cleanup, nil
}

// remoteUploadDir uploads every file in a local directory under a remote prefix URI.
func remoteUploadDir(localDir, uri string) error {
	ctx := context.Background()
	if !cloud.IsWritable(uri) {
		return fmt.Errorf("scheme is read-only: %q", uri)
	}
	store, err := storeFor(ctx, uri)
	if err != nil {
		return err
	}

	prefixURI := uri
	if !strings.HasSuffix(prefixURI, "/") {
		prefixURI += "/"
	}

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
		objURI := prefixURI + filepath.ToSlash(relPath)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		return store.Upload(ctx, objURI, f, info.Size())
	})
}

// remoteDownloadToReader downloads a remote URI into memory and returns a reader.
func remoteDownloadToReader(uri string) (io.Reader, int64, string, error) {
	ctx := context.Background()
	store, err := storeFor(ctx, uri)
	if err != nil {
		return nil, 0, "", err
	}
	data, err := store.Download(ctx, uri)
	if err != nil {
		return nil, 0, "", err
	}
	name := filepath.Base(uri)
	return bytes.NewReader(data), int64(len(data)), name, nil
}
