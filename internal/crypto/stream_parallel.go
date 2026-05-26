package crypto

import (
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/Skpow1234/Vaultpack/internal/util"
)

// EncryptStreamParallel reads plaintext chunks from r, encrypts them in parallel
// using `workers` goroutines, and writes the resulting ciphertext (in original
// chunk order) to w. The output format is identical to EncryptStream so the
// regular DecryptStream can decrypt it.
//
//   - workers <= 1: falls back to the sequential EncryptStream.
//   - workers <= 0 and < 0: 1 worker.
//   - 0: interpreted as runtime.NumCPU.
//
// All workers create their own AEAD instances; the underlying key is shared.
func EncryptStreamParallel(r io.Reader, w io.Writer, key, aad []byte, chunkSize int, cipherName string, workers int) (*StreamEncryptResult, error) {
	if workers == 0 {
		workers = runtime.NumCPU()
	}
	if workers <= 1 {
		return EncryptStream(r, w, key, aad, chunkSize, cipherName)
	}

	if cipherName == "" {
		cipherName = CipherAES256GCM
	}
	probe, err := NewAEAD(cipherName, key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	baseNonce, err := GenerateNonce(probe.NonceSize())
	if err != nil {
		return nil, err
	}
	tagSize := probe.Overhead()

	type task struct {
		idx    uint64
		data   []byte
		isLast bool
	}
	type result struct {
		idx    uint64
		sealed []byte
	}

	tasks := make(chan task, workers*2)
	results := make(chan result, workers*2)

	// Reader goroutine: reads chunks with one-ahead lookahead to mark the last.
	var readErr error
	go func() {
		defer close(tasks)
		buf := make([]byte, chunkSize)
		var idx uint64
		var pending []byte
		var hasPending bool
		for {
			n, err := io.ReadFull(r, buf)
			if hasPending {
				if n > 0 || err == nil {
					// Not last.
					chunk := make([]byte, len(pending))
					copy(chunk, pending)
					tasks <- task{idx: idx, data: chunk, isLast: false}
					idx++
				}
			}
			if n > 0 {
				pending = make([]byte, n)
				copy(pending, buf[:n])
				hasPending = true
			}
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					break
				}
				readErr = fmt.Errorf("read chunk: %w", err)
				return
			}
		}
		// Emit the final chunk.
		if hasPending {
			tasks <- task{idx: idx, data: pending, isLast: true}
		} else {
			// Empty input: still emit one (empty) final chunk to match EncryptStream.
			tasks <- task{idx: 0, data: nil, isLast: true}
		}
	}()

	// Worker goroutines: each owns its own AEAD instance.
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aead, err := NewAEAD(cipherName, key)
			if err != nil {
				// This should not happen because probe succeeded above.
				return
			}
			for t := range tasks {
				counter := t.idx
				if t.isLast {
					counter |= lastChunkFlag
				}
				nonce := deriveNonce(baseNonce, counter)
				sealed := aead.Seal(nil, nonce, t.data, aad)
				// Encode isLast in the high bit of the result index for ordering.
				key := t.idx
				if t.isLast {
					key |= lastChunkFlag
				}
				results <- result{idx: key, sealed: sealed}
			}
		}()
	}

	// Closer goroutine.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Writer: gather results, reorder by original index, and write in order.
	// We store all chunks (including the last) by true index in `pending` and
	// drain contiguous prefixes. The last chunk's index is remembered so we can
	// stop after writing it.
	pending := make(map[uint64][]byte)
	var nextIdx uint64
	var totalWritten int64
	var lastTag []byte
	lastIdx := ^uint64(0) // sentinel: unknown
	for r := range results {
		isLast := (r.idx & lastChunkFlag) != 0
		idx := r.idx &^ lastChunkFlag
		if isLast {
			lastIdx = idx
		}
		pending[idx] = r.sealed

		for {
			seg, ok := pending[nextIdx]
			if !ok {
				break
			}
			n, err := w.Write(seg)
			if err != nil {
				return nil, fmt.Errorf("write chunk %d: %w", nextIdx, err)
			}
			totalWritten += int64(n)
			lastTag = seg[len(seg)-tagSize:]
			delete(pending, nextIdx)
			nextIdx++
		}
	}

	if readErr != nil {
		return nil, readErr
	}
	// After all workers are done, lastIdx must be known and equal to nextIdx-1.
	if lastIdx == ^uint64(0) || nextIdx == 0 || nextIdx-1 != lastIdx {
		return nil, fmt.Errorf("%w: ordering bug: nextIdx=%d lastIdx=%d pending=%d", util.ErrDecryptFailed, nextIdx, lastIdx, len(pending))
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("%w: %d chunks left unwritten", util.ErrDecryptFailed, len(pending))
	}

	return &StreamEncryptResult{
		BaseNonce:      baseNonce,
		LastTag:        lastTag,
		CiphertextSize: totalWritten,
	}, nil
}
