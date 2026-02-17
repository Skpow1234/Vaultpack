package crypto

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// DefaultChunkSize is the default plaintext chunk size for streaming encryption (64 KB).
	// Good balance for small and large files; configurable via config chunk_size.
	DefaultChunkSize = 64 * 1024
	// MaxChunkSizeRecommended is the recommended maximum chunk size (1 MiB).
	// Larger chunks use more memory per chunk; there is no hard limit (chunk index is uint64).
	MaxChunkSizeRecommended = 1024 * 1024
	// lastChunkFlag is set on bit 63 of the counter for the final chunk to prevent truncation.
	lastChunkFlag = uint64(1) << 63
)

// Streaming and memory: EncryptStream and DecryptStream process one chunk at a time and use
// O(chunkSize) memory (one plaintext chunk buffer, one ciphertext chunk buffer). The full file
// is never loaded inside these functions. The CLI may buffer full plaintext for hashing and
// optional compression before calling EncryptStream. There is no artificial file size limit;
// the chunk counter is uint64 (last-chunk flag uses bit 63).

// StreamEncryptResult holds metadata from a streaming encryption operation.
type StreamEncryptResult struct {
	BaseNonce      []byte // nonce (size depends on cipher)
	LastTag        []byte // tag of the final chunk
	CiphertextSize int64  // total bytes written (ciphertext + tags)
}

// EncryptStream reads plaintext from r in chunks, encrypts each chunk with the
// named AEAD cipher using a derived nonce, and writes the ciphertext+tag to w.
//
// Nonce derivation: baseNonce XOR (8-byte big-endian chunk index, right-aligned).
// The final chunk has bit 63 set on the counter to prevent truncation attacks.
func EncryptStream(r io.Reader, w io.Writer, key, aad []byte, chunkSize int, cipherName string) (*StreamEncryptResult, error) {
	if cipherName == "" {
		cipherName = CipherAES256GCM // backward compat default
	}

	aead, err := NewAEAD(cipherName, key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	baseNonce, err := GenerateNonce(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	tagSize := aead.Overhead()

	buf := make([]byte, chunkSize)
	var (
		chunkIdx       uint64
		totalWritten   int64
		lastTag        []byte
		pendingData    []byte
		pendingHasData bool
	)

	for {
		n, readErr := io.ReadFull(r, buf)

		if pendingHasData {
			if n > 0 || readErr == nil {
				// Previous chunk is NOT the last.
				nonce := deriveNonce(baseNonce, chunkIdx)
				sealed := aead.Seal(nil, nonce, pendingData, aad)
				written, wErr := w.Write(sealed)
				if wErr != nil {
					return nil, fmt.Errorf("write chunk %d: %w", chunkIdx, wErr)
				}
				totalWritten += int64(written)
				lastTag = sealed[len(sealed)-tagSize:]
				chunkIdx++
			}
		}

		if n > 0 {
			pendingData = make([]byte, n)
			copy(pendingData, buf[:n])
			pendingHasData = true
		}

		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("read chunk: %w", readErr)
		}
	}

	// Encrypt the final chunk with the last-chunk flag.
	if pendingHasData {
		nonce := deriveNonce(baseNonce, chunkIdx|lastChunkFlag)
		sealed := aead.Seal(nil, nonce, pendingData, aad)
		written, wErr := w.Write(sealed)
		if wErr != nil {
			return nil, fmt.Errorf("write final chunk: %w", wErr)
		}
		totalWritten += int64(written)
		lastTag = sealed[len(sealed)-tagSize:]
	} else {
		// Empty input: encrypt an empty final chunk.
		nonce := deriveNonce(baseNonce, lastChunkFlag)
		sealed := aead.Seal(nil, nonce, nil, aad)
		written, wErr := w.Write(sealed)
		if wErr != nil {
			return nil, fmt.Errorf("write empty final chunk: %w", wErr)
		}
		totalWritten += int64(written)
		lastTag = sealed[len(sealed)-tagSize:]
	}

	return &StreamEncryptResult{
		BaseNonce:      baseNonce,
		LastTag:        lastTag,
		CiphertextSize: totalWritten,
	}, nil
}

// DecryptStream reads chunked ciphertext from r, decrypts each chunk, and writes
// plaintext to w. chunkSize is the original plaintext chunk size.
func DecryptStream(r io.Reader, w io.Writer, key, baseNonce, aad []byte, chunkSize int, cipherName string) error {
	if cipherName == "" {
		cipherName = CipherAES256GCM
	}

	aead, err := NewAEAD(cipherName, key)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}

	if len(baseNonce) != aead.NonceSize() {
		return fmt.Errorf("%w: got %d bytes, want %d", util.ErrInvalidNonceLength, len(baseNonce), aead.NonceSize())
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	tagSize := aead.Overhead()
	encChunkSize := chunkSize + tagSize
	buf := make([]byte, encChunkSize)
	var chunkIdx uint64

	// Read the first chunk (lookahead to detect final chunk).
	currentN, currentErr := io.ReadFull(r, buf)
	if currentN == 0 && (currentErr == io.EOF || currentErr == io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: empty ciphertext", util.ErrDecryptFailed)
	}

	for {
		currentData := make([]byte, currentN)
		copy(currentData, buf[:currentN])

		// Peek ahead to see if there's another chunk.
		nextN, nextErr := io.ReadFull(r, buf)

		isLast := (nextN == 0 && (nextErr == io.EOF || nextErr == io.ErrUnexpectedEOF))

		var nonce []byte
		if isLast {
			nonce = deriveNonce(baseNonce, chunkIdx|lastChunkFlag)
		} else {
			nonce = deriveNonce(baseNonce, chunkIdx)
		}

		plaintext, err := aead.Open(nil, nonce, currentData, aad)
		if err != nil {
			return fmt.Errorf("%w: chunk %d: %v", util.ErrDecryptFailed, chunkIdx, err)
		}

		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("write plaintext chunk %d: %w", chunkIdx, err)
		}

		if isLast {
			break
		}

		chunkIdx++
		currentN = nextN
		currentErr = nextErr

		if currentErr != nil && currentErr != io.EOF && currentErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("read chunk %d: %w", chunkIdx, currentErr)
		}
	}

	return nil
}

// deriveNonce XORs a counter into the last 8 bytes of the base nonce.
// Works with any nonce size >= 8.
func deriveNonce(baseNonce []byte, counter uint64) []byte {
	nonceSize := len(baseNonce)
	nonce := make([]byte, nonceSize)
	copy(nonce, baseNonce)
	// XOR counter into the last 8 bytes.
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	offset := nonceSize - 8
	for i := 0; i < 8; i++ {
		nonce[offset+i] ^= counterBytes[i]
	}
	return nonce
}
