package crypto

import (
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// DecryptStreamParallel reads chunked ciphertext from r, decrypts chunks in
// parallel with `workers` goroutines, and writes plaintext to w in chunk order.
// Falls back to the sequential DecryptStream when workers <= 1. Use 0 to mean
// runtime.NumCPU.
func DecryptStreamParallel(r io.Reader, w io.Writer, key, baseNonce, aad []byte, chunkSize int, cipherName string, workers int) error {
	if workers == 0 {
		workers = runtime.NumCPU()
	}
	if workers <= 1 {
		return DecryptStream(r, w, key, baseNonce, aad, chunkSize, cipherName)
	}

	if cipherName == "" {
		cipherName = CipherAES256GCM
	}
	probe, err := NewAEAD(cipherName, key)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}
	if len(baseNonce) != probe.NonceSize() {
		return fmt.Errorf("%w: got %d bytes, want %d", util.ErrInvalidNonceLength, len(baseNonce), probe.NonceSize())
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	tagSize := probe.Overhead()
	encChunkSize := chunkSize + tagSize

	type task struct {
		idx    uint64
		data   []byte
		isLast bool
	}
	type result struct {
		idx       uint64
		plaintext []byte
		err       error
	}

	tasks := make(chan task, workers*2)
	results := make(chan result, workers*2)

	var readErr error
	go func() {
		defer close(tasks)
		buf := make([]byte, encChunkSize)
		currentN, currentErr := io.ReadFull(r, buf)
		if currentN == 0 && (currentErr == io.EOF || currentErr == io.ErrUnexpectedEOF) {
			readErr = fmt.Errorf("%w: empty ciphertext", util.ErrDecryptFailed)
			return
		}
		var idx uint64
		for {
			currentData := make([]byte, currentN)
			copy(currentData, buf[:currentN])
			nextN, nextErr := io.ReadFull(r, buf)
			isLast := (nextN == 0 && (nextErr == io.EOF || nextErr == io.ErrUnexpectedEOF))

			tasks <- task{idx: idx, data: currentData, isLast: isLast}
			if isLast {
				return
			}
			idx++
			currentN = nextN
			currentErr = nextErr
			if currentErr != nil && currentErr != io.EOF && currentErr != io.ErrUnexpectedEOF {
				readErr = fmt.Errorf("read chunk %d: %w", idx, currentErr)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aead, err := NewAEAD(cipherName, key)
			if err != nil {
				return
			}
			for t := range tasks {
				counter := t.idx
				if t.isLast {
					counter |= lastChunkFlag
				}
				nonce := deriveNonce(baseNonce, counter)
				pt, err := aead.Open(nil, nonce, t.data, aad)
				key := t.idx
				if t.isLast {
					key |= lastChunkFlag
				}
				results <- result{idx: key, plaintext: pt, err: err}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	pending := make(map[uint64][]byte)
	var nextIdx uint64
	lastIdx := ^uint64(0)
	for r := range results {
		if r.err != nil {
			isLast := (r.idx & lastChunkFlag) != 0
			idx := r.idx &^ lastChunkFlag
			_ = isLast
			return fmt.Errorf("%w: chunk %d: %v", util.ErrDecryptFailed, idx, r.err)
		}
		isLast := (r.idx & lastChunkFlag) != 0
		idx := r.idx &^ lastChunkFlag
		if isLast {
			lastIdx = idx
		}
		pending[idx] = r.plaintext

		for {
			seg, ok := pending[nextIdx]
			if !ok {
				break
			}
			if _, err := w.Write(seg); err != nil {
				return fmt.Errorf("write plaintext chunk %d: %w", nextIdx, err)
			}
			delete(pending, nextIdx)
			nextIdx++
		}
	}

	if readErr != nil {
		return readErr
	}
	if lastIdx == ^uint64(0) || nextIdx == 0 || nextIdx-1 != lastIdx || len(pending) > 0 {
		return fmt.Errorf("%w: decryptor ordering bug: nextIdx=%d lastIdx=%d pending=%d", util.ErrDecryptFailed, nextIdx, lastIdx, len(pending))
	}
	return nil
}
