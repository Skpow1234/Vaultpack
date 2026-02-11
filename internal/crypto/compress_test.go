package crypto

import (
	"bytes"
	"testing"
)

func TestSupportedCompression(t *testing.T) {
	for _, algo := range SupportedCompressionAlgos {
		if !SupportedCompression(algo) {
			t.Errorf("SupportedCompression(%q) = false, want true", algo)
		}
	}
	if SupportedCompression("lz4") {
		t.Error("SupportedCompression(lz4) = true, want false")
	}
}

func TestCompressDecompress_AllAlgos(t *testing.T) {
	// Use a large-ish repeated payload so compression actually shrinks it.
	original := bytes.Repeat([]byte("VaultPack compression test data. "), 1000)

	for _, algo := range []string{CompressGzip, CompressZstd} {
		t.Run(algo, func(t *testing.T) {
			compressed, err := Compress(original, algo)
			if err != nil {
				t.Fatalf("Compress(%s): %v", algo, err)
			}

			// Compressed should be smaller than original for repetitive data.
			if len(compressed) >= len(original) {
				t.Errorf("Compress(%s): compressed size %d >= original %d", algo, len(compressed), len(original))
			}

			decompressed, err := Decompress(compressed, algo)
			if err != nil {
				t.Fatalf("Decompress(%s): %v", algo, err)
			}

			if !bytes.Equal(decompressed, original) {
				t.Errorf("Decompress(%s): round-trip mismatch", algo)
			}
		})
	}
}

func TestCompressDecompress_None(t *testing.T) {
	data := []byte("no compression")
	out, err := Compress(data, CompressNone)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Error("CompressNone should return data unchanged")
	}

	out, err = Decompress(data, CompressNone)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Error("DecompressNone should return data unchanged")
	}
}

func TestCompressDecompress_EmptyData(t *testing.T) {
	for _, algo := range []string{CompressGzip, CompressZstd} {
		t.Run(algo, func(t *testing.T) {
			compressed, err := Compress([]byte{}, algo)
			if err != nil {
				t.Fatalf("Compress empty: %v", err)
			}
			decompressed, err := Decompress(compressed, algo)
			if err != nil {
				t.Fatalf("Decompress empty: %v", err)
			}
			if len(decompressed) != 0 {
				t.Errorf("expected empty, got %d bytes", len(decompressed))
			}
		})
	}
}

func TestCompress_UnsupportedAlgo(t *testing.T) {
	_, err := Compress([]byte("test"), "lz4")
	if err == nil {
		t.Error("expected error for unsupported algo")
	}
}

func TestDecompress_UnsupportedAlgo(t *testing.T) {
	_, err := Decompress([]byte("test"), "lz4")
	if err == nil {
		t.Error("expected error for unsupported algo")
	}
}

func TestDecompress_CorruptedData(t *testing.T) {
	for _, algo := range []string{CompressGzip, CompressZstd} {
		t.Run(algo, func(t *testing.T) {
			_, err := Decompress([]byte("not valid compressed data"), algo)
			if err == nil {
				t.Errorf("Decompress(%s) with corrupt data should fail", algo)
			}
		})
	}
}
