// Package cloud provides a unified abstraction over remote object stores
// (Azure Blob, AWS S3, Google Cloud Storage) and read-only HTTPS for
// VaultPack's --in/--out support.
//
// Supported URI schemes:
//
//	az://container/path/to/blob       Azure Blob Storage
//	s3://bucket/path/to/object         AWS S3
//	gs://bucket/path/to/object         Google Cloud Storage
//	https://host/path                  HTTPS download (read-only)
//
// Credentials follow each SDK's default chain (env vars, shared credentials
// file, IAM/instance metadata, etc.) unless overridden via CLI flags.
package cloud

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Scheme identifies the remote storage backend for a URI.
type Scheme string

const (
	SchemeAzure Scheme = "az"
	SchemeS3    Scheme = "s3"
	SchemeGCS   Scheme = "gs"
	SchemeHTTPS Scheme = "https"
	SchemeHTTP  Scheme = "http"
	SchemeLocal Scheme = ""
)

// DetectScheme returns the Scheme for a URI or SchemeLocal if it's a local path.
func DetectScheme(uri string) Scheme {
	switch {
	case strings.HasPrefix(uri, "az://"):
		return SchemeAzure
	case strings.HasPrefix(uri, "s3://"):
		return SchemeS3
	case strings.HasPrefix(uri, "gs://"):
		return SchemeGCS
	case strings.HasPrefix(uri, "https://"):
		return SchemeHTTPS
	case strings.HasPrefix(uri, "http://"):
		return SchemeHTTP
	default:
		return SchemeLocal
	}
}

// IsRemote reports whether uri refers to a remote storage backend.
func IsRemote(uri string) bool {
	return DetectScheme(uri) != SchemeLocal
}

// IsWritable reports whether the URI scheme supports uploads.
// HTTPS/HTTP are read-only; az/s3/gs are read-write; local is always writable.
func IsWritable(uri string) bool {
	switch DetectScheme(uri) {
	case SchemeHTTPS, SchemeHTTP:
		return false
	default:
		return true
	}
}

// ParseBucketKey splits a URI like `<scheme>://bucket/key/path` into
// (bucket, key). Returns an empty key if there is no path component.
func ParseBucketKey(uri string) (bucket, key string, err error) {
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid URI: %q", uri)
	}
	rest := uri[idx+3:]
	if rest == "" {
		return "", "", fmt.Errorf("empty URI body: %q", uri)
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return rest, "", nil
	}
	bucket = rest[:slash]
	key = rest[slash+1:]
	if bucket == "" {
		return "", "", fmt.Errorf("empty bucket in URI %q", uri)
	}
	return bucket, key, nil
}

// Store is the minimal blob-store interface used by VaultPack's CLI for
// remote --in/--out support. Implementations are constructed per scheme.
type Store interface {
	// Scheme returns the URI scheme this store handles ("az", "s3", "gs", "https").
	Scheme() Scheme

	// Download reads the object at uri and returns its contents.
	Download(ctx context.Context, uri string) ([]byte, error)

	// DownloadToWriter streams the object at uri into w.
	DownloadToWriter(ctx context.Context, uri string, w io.Writer) error

	// Upload writes data from r (of total size bytes) to uri.
	// Implementations may return ErrReadOnly when the scheme does not support uploads.
	Upload(ctx context.Context, uri string, r io.Reader, size int64) error

	// List returns the names of objects under the given prefix URI.
	// Implementations may return ErrNotSupported when listing is not available.
	List(ctx context.Context, prefixURI string) ([]string, error)
}

// ErrReadOnly is returned by Upload on read-only stores (HTTPS).
var ErrReadOnly = fmt.Errorf("cloud: store is read-only")

// ErrNotSupported is returned for operations the store does not implement.
var ErrNotSupported = fmt.Errorf("cloud: operation not supported")
