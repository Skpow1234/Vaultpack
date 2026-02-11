package crypto

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Compression algorithm names.
const (
	CompressNone = "none"
	CompressGzip = "gzip"
	CompressZstd = "zstd"
)

// SupportedCompressionAlgos is the ordered list of all supported compression algorithms.
var SupportedCompressionAlgos = []string{
	CompressNone,
	CompressGzip,
	CompressZstd,
}

// SupportedCompression checks whether the given algorithm name is supported.
func SupportedCompression(algo string) bool {
	switch algo {
	case CompressNone, CompressGzip, CompressZstd:
		return true
	default:
		return false
	}
}

// Compress compresses data using the specified algorithm.
// Returns the compressed bytes and nil error on success.
// For CompressNone the input is returned as-is.
func Compress(data []byte, algo string) ([]byte, error) {
	switch algo {
	case CompressNone:
		return data, nil

	case CompressGzip:
		var buf bytes.Buffer
		w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("gzip writer: %w", err)
		}
		if _, err := w.Write(data); err != nil {
			return nil, fmt.Errorf("gzip write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("gzip close: %w", err)
		}
		return buf.Bytes(), nil

	case CompressZstd:
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return nil, fmt.Errorf("zstd encoder: %w", err)
		}
		defer encoder.Close()
		return encoder.EncodeAll(data, nil), nil

	default:
		return nil, fmt.Errorf("unsupported compression algorithm %q", algo)
	}
}

// Decompress decompresses data using the specified algorithm.
// For CompressNone the input is returned as-is.
func Decompress(data []byte, algo string) ([]byte, error) {
	switch algo {
	case CompressNone:
		return data, nil

	case CompressGzip:
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress: %w", err)
		}
		return out, nil

	case CompressZstd:
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			return nil, fmt.Errorf("zstd decoder: %w", err)
		}
		defer decoder.Close()
		out, err := decoder.DecodeAll(data, nil)
		if err != nil {
			return nil, fmt.Errorf("zstd decompress: %w", err)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unsupported compression algorithm %q", algo)
	}
}
