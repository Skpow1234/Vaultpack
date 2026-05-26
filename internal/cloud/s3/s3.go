// Package s3 provides an AWS S3 implementation of the cloud.Store interface.
//
// URI scheme:
//
//	s3://bucket/path/to/object
//
// Credentials are resolved via the AWS SDK v2 default credential chain:
//
//  1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
//     AWS_SESSION_TOKEN, AWS_PROFILE, AWS_REGION).
//  2. Shared credentials file (~/.aws/credentials).
//  3. IAM Roles for Tasks / EC2 instance metadata (IMDSv2).
//
// Region is resolved from AWS_REGION / AWS_DEFAULT_REGION env vars or the
// shared config file. Bucket-region detection happens automatically via the
// SDK's `s3.NewFromConfig` when the bucket lives in a different region.
package s3

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsmanager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
)

// Store implements cloud.Store for AWS S3.
type Store struct {
	client *s3.Client
}

// Options configures the S3 store.
type Options struct {
	// Region overrides the SDK default-resolved region. Optional.
	Region string
	// Profile selects a named AWS profile from the shared config. Optional.
	Profile string
	// Endpoint overrides the S3 endpoint URL (for MinIO, LocalStack, etc.). Optional.
	Endpoint string
	// UsePathStyle forces path-style addressing (required for some S3-compatible services).
	UsePathStyle bool
}

// NewStore builds an S3 Store with the given options.
func NewStore(ctx context.Context, opts Options) (*Store, error) {
	cfgOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(opts.Region))
	}
	if opts.Profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(opts.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	clientOpts := []func(*s3.Options){}
	if opts.Endpoint != "" {
		ep := opts.Endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	if opts.UsePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}
	return &Store{client: s3.NewFromConfig(cfg, clientOpts...)}, nil
}

// Scheme returns "s3".
func (s *Store) Scheme() cloud.Scheme { return cloud.SchemeS3 }

// Download reads an S3 object into memory.
func (s *Store) Download(ctx context.Context, uri string) ([]byte, error) {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get %s/%s: %w", bucket, key, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 read %s/%s: %w", bucket, key, err)
	}
	return data, nil
}

// DownloadToWriter streams an S3 object into w.
func (s *Store) DownloadToWriter(ctx context.Context, uri string, w io.Writer) error {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 get %s/%s: %w", bucket, key, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("s3 stream %s/%s: %w", bucket, key, err)
	}
	return nil
}

// Upload writes data from r to an S3 object using the multipart manager.
// The size hint is advisory; the uploader handles arbitrary streams.
func (s *Store) Upload(ctx context.Context, uri string, r io.Reader, size int64) error {
	bucket, key, err := cloud.ParseBucketKey(uri)
	if err != nil {
		return err
	}
	uploader := awsmanager.NewUploader(s.client)
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   r,
	})
	if err != nil {
		return fmt.Errorf("s3 put %s/%s: %w", bucket, key, err)
	}
	return nil
}

// List returns object keys under the given prefix URI.
func (s *Store) List(ctx context.Context, prefixURI string) ([]string, error) {
	bucket, prefix, err := cloud.ParseBucketKey(prefixURI)
	if err != nil {
		return nil, err
	}
	var out []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 list %s/%s: %w", bucket, prefix, err)
		}
		for _, o := range page.Contents {
			if o.Key != nil {
				out = append(out, *o.Key)
			}
		}
	}
	return out, nil
}

// Ensure Store satisfies cloud.Store at compile time.
var _ cloud.Store = (*Store)(nil)

// Suppress unused import warning for s3types when no error types are referenced here.
var _ = s3types.NoSuchKey{}
