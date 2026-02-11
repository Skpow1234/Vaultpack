package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

const (
	// DefaultChunkSize is the default plaintext chunk size for streaming encryption (64 KB).
	DefaultChunkSize = 64 * 1024
	// lastChunkFlag is set on bit 63 of the counter for the final chunk to prevent truncation.
	lastChunkFlag = uint64(1) << 63
)

// StreamEncryptResult holds metadata from a streaming encryption operation.
type StreamEncryptResult struct {
	BaseNonce      []byte // 12-byte base nonce
	LastTag        []byte // 16-byte tag of the final chunk
	CiphertextSize int64  // total bytes written (ciphertext + tags)
}

// EncryptStream reads plaintext from r in chunks, encrypts each chunk with AES-256-GCM
// using a derived nonce, and writes the ciphertext+tag to w.
//
// Nonce derivation: baseNonce XOR (8-byte big-endian chunk index, left-padded with 4 zero bytes).
// The final chunk has bit 63 set on the counter to prevent truncation attacks.
func EncryptStream(r io.Reader, w io.Writer, key, aad []byte, chunkSize int) (*StreamEncryptResult, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", util.ErrInvalidKeyLength, len(key))
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	baseNonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

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
			// Encrypt the previous chunk (it's not the last one since we got more data or need to check).
			if n > 0 || readErr == nil {
				// Previous chunk is NOT the last.
				nonce := deriveNonce(baseNonce, chunkIdx)
				sealed := gcm.Seal(nil, nonce, pendingData, aad)
				written, wErr := w.Write(sealed)
				if wErr != nil {
					return nil, fmt.Errorf("write chunk %d: %w", chunkIdx, wErr)
				}
				totalWritten += int64(written)
				lastTag = sealed[len(sealed)-GCMTagSize:]
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
		sealed := gcm.Seal(nil, nonce, pendingData, aad)
		written, wErr := w.Write(sealed)
		if wErr != nil {
			return nil, fmt.Errorf("write final chunk: %w", wErr)
		}
		totalWritten += int64(written)
		lastTag = sealed[len(sealed)-GCMTagSize:]
	} else {
		// Empty input: encrypt an empty final chunk.
		nonce := deriveNonce(baseNonce, lastChunkFlag)
		sealed := gcm.Seal(nil, nonce, nil, aad)
		written, wErr := w.Write(sealed)
		if wErr != nil {
			return nil, fmt.Errorf("write empty final chunk: %w", wErr)
		}
		totalWritten += int64(written)
		lastTag = sealed[len(sealed)-GCMTagSize:]
	}

	return &StreamEncryptResult{
		BaseNonce:      baseNonce,
		LastTag:        lastTag,
		CiphertextSize: totalWritten,
	}, nil
}

// DecryptStream reads chunked ciphertext from r, decrypts each chunk, and writes
// plaintext to w. chunkSize is the original plaintext chunk size (each encrypted
// chunk is chunkSize + GCMTagSize bytes, except the last which may be smaller).
func DecryptStream(r io.Reader, w io.Writer, key, baseNonce, aad []byte, chunkSize int) error {
	if len(key) != AES256KeySize {
		return fmt.Errorf("%w: got %d bytes", util.ErrInvalidKeyLength, len(key))
	}
	if len(baseNonce) != GCMNonceSize {
		return fmt.Errorf("%w: got %d bytes", util.ErrInvalidNonceLength, len(baseNonce))
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	encChunkSize := chunkSize + GCMTagSize
	buf := make([]byte, encChunkSize)
	var chunkIdx uint64

	// We need lookahead to detect the final chunk.
	// Read the first chunk.
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

		plaintext, err := gcm.Open(nil, nonce, currentData, aad)
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
func deriveNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, GCMNonceSize)
	copy(nonce, baseNonce)
	// XOR counter into bytes 4..11 (last 8 bytes).
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= counterBytes[i]
	}
	return nonce
}
