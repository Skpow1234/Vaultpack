// Package gcs provides a Google Cloud Storage implementation of cloud.Store.
//
// URI scheme:
//
//	gs://bucket/path/to/object
//
// Credentials are resolved via Application Default Credentials (ADC):
//
//  1. GOOGLE_APPLICATION_CREDENTIALS environment variable pointing at a JSON key file.
//  2. `gcloud auth application-default login` credentials in $HOME/.config/gcloud.
//  3. GCE/Cloud Run metadata server when running on Google Cloud.
package gcs

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
)

// Store implements cloud.Store for Google Cloud Storage.
type Store struct {
	client *storage.Client
}

// Options reserved for future configuration (e.g. credentials JSON path,
// custom endpoint). Currently empty since GCS resolves everything via ADC.
type Options struct{}

// NewStore constructs a GCS Store using Application Default Credentials.
func NewStore(ctx context.Context, _ Options) (*Store, error) {
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs client: %w", err)
	}
	return &Store{client: c}, nil
}

// Close releases the underlying GCS client.
func (s *Store) Close() error { return s.client.Close() }

// Scheme returns "gs".
func (s *Store) Scheme() cloud.Scheme { return cloud.SchemeGCS }

// Download reads a GCS object into memory.
func (s *Store) Download(ctx context.Context, uri string) ([]byte, error) {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return nil, err
	}
	r, err := s.client.Bucket(bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs get %s/%s: %w", bucket, key, err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gcs read %s/%s: %w", bucket, key, err)
	}
	return data, nil
}

// DownloadToWriter streams a GCS object into w.
func (s *Store) DownloadToWriter(ctx context.Context, uri string, w io.Writer) error {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return err
	}
	r, err := s.client.Bucket(bucket).Object(key).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("gcs get %s/%s: %w", bucket, key, err)
	}
	defer r.Close()
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("gcs stream %s/%s: %w", bucket, key, err)
	}
	return nil
}

// Upload writes data from r to a GCS object.
// The size hint is currently advisory; the GCS writer streams arbitrary-length input.
func (s *Store) Upload(ctx context.Context, uri string, r io.Reader, size int64) error {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return err
	}
	w := s.client.Bucket(bucket).Object(key).NewWriter(ctx)
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return fmt.Errorf("gcs upload %s/%s: %w", bucket, key, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gcs close %s/%s: %w", bucket, key, err)
	}
	return nil
}

// List returns object names under the given prefix URI.
func (s *Store) List(ctx context.Context, prefixURI string) ([]string, error) {
	bucket, prefix, err := cloud.ParseBucketKey(prefixURI)
	if err != nil {
		return nil, err
	}
	it := s.client.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: prefix})
	var out []string
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcs list %s/%s: %w", bucket, prefix, err)
		}
		out = append(out, attrs.Name)
	}
	return out, nil
}

var _ cloud.Store = (*Store)(nil)
