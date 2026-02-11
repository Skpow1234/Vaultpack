package bundle

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	payloadEntry   = "payload.bin"
	manifestEntry  = "manifest.json"
	signatureEntry = "signature.sig"
)

// WriteParams holds everything needed to create a .vpack bundle.
type WriteParams struct {
	OutputPath    string
	Ciphertext    []byte    // used for non-streaming writes
	Payload       io.Reader // used for streaming writes (takes precedence over Ciphertext)
	ManifestBytes []byte
	Signature     []byte    // optional; nil if unsigned
	Writer        io.Writer // optional; if set, write to this instead of OutputPath
}

// Write creates a .vpack ZIP file containing payload.bin and manifest.json,
// and optionally signature.sig.
func Write(p *WriteParams) error {
	var w io.Writer
	if p.Writer != nil {
		w = p.Writer
	} else {
		f, err := os.Create(p.OutputPath)
		if err != nil {
			return fmt.Errorf("create bundle: %w", err)
		}
		defer f.Close()
		w = f
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Write payload.bin.
	pw, err := zw.Create(payloadEntry)
	if err != nil {
		return fmt.Errorf("create payload entry: %w", err)
	}
	if p.Payload != nil {
		if _, err := io.Copy(pw, p.Payload); err != nil {
			return fmt.Errorf("write payload stream: %w", err)
		}
	} else {
		if _, err := pw.Write(p.Ciphertext); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	// Write manifest.json.
	mw, err := zw.Create(manifestEntry)
	if err != nil {
		return fmt.Errorf("create manifest entry: %w", err)
	}
	if _, err := mw.Write(p.ManifestBytes); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// Optionally write signature.sig.
	if p.Signature != nil {
		sw, err := zw.Create(signatureEntry)
		if err != nil {
			return fmt.Errorf("create signature entry: %w", err)
		}
		if _, err := sw.Write(p.Signature); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
	}

	return nil
}

// ReadResult holds the extracted contents of a .vpack bundle.
type ReadResult struct {
	Ciphertext    []byte
	ManifestBytes []byte
	Manifest      *Manifest
	Signature     []byte // nil if no signature present
}

// Read opens a .vpack ZIP file and extracts its contents.
func Read(path string) (*ReadResult, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer zr.Close()

	result := &ReadResult{}

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open entry %q: %w", f.Name, err)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read entry %q: %w", f.Name, err)
		}

		switch f.Name {
		case payloadEntry:
			result.Ciphertext = data
		case manifestEntry:
			result.ManifestBytes = data
		case signatureEntry:
			result.Signature = data
		}
	}

	if result.Ciphertext == nil {
		return nil, fmt.Errorf("%w: missing %s", util.ErrBundleCorrupted, payloadEntry)
	}
	if result.ManifestBytes == nil {
		return nil, fmt.Errorf("%w: missing %s", util.ErrBundleCorrupted, manifestEntry)
	}

	// Parse and validate manifest.
	m, err := UnmarshalManifest(result.ManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", util.ErrManifestInvalid, err)
	}
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	result.Manifest = m

	return result, nil
}

// ReadManifestOnly opens a .vpack and returns just the parsed manifest
// without loading the full ciphertext into memory.
func ReadManifestOnly(path string) (*Manifest, []byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open bundle: %w", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name == manifestEntry {
			rc, err := f.Open()
			if err != nil {
				return nil, nil, fmt.Errorf("open manifest entry: %w", err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, nil, fmt.Errorf("read manifest: %w", err)
			}
			m, err := UnmarshalManifest(data)
			if err != nil {
				return nil, nil, err
			}
			return m, data, nil
		}
	}

	return nil, nil, fmt.Errorf("%w: missing %s", util.ErrBundleCorrupted, manifestEntry)
}

// ReadRaw returns raw bytes for a specific entry in the bundle.
func ReadRaw(path, entryName string) ([]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name == entryName {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open entry %q: %w", entryName, err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("entry %q not found in bundle", entryName)
}

// WriteToFile is a convenience to write raw bytes to a file path.
func WriteToFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// ReadFile reads the full contents of a file.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// StreamToBytes reads an io.Reader fully into a byte slice.
func StreamToBytes(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
