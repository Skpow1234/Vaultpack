package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BatchFileEntry holds one file to be processed in a batch.
type BatchFileEntry struct {
	InputPath  string // absolute or relative path to input file
	OutputPath string // absolute or relative path to output file
	RelPath    string // path relative to the source dir (for display)
}

// BatchResult stores the outcome of processing one file.
type BatchResult struct {
	RelPath    string `json:"rel_path"`
	InputPath  string `json:"input_path"`
	OutputPath string `json:"output_path"`
	Status     string `json:"status"` // "ok" or "error"
	Error      string `json:"error,omitempty"`
	Duration   string `json:"duration"`
}

// BatchManifest is the batch-manifest.json written after a batch operation.
type BatchManifest struct {
	Operation string        `json:"operation"` // "protect" or "decrypt"
	CreatedAt string        `json:"created_at"`
	SourceDir string        `json:"source_dir"`
	OutputDir string        `json:"output_dir"`
	Workers   int           `json:"workers"`
	Total     int           `json:"total"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
	Results   []BatchResult `json:"results"`
}

// collectFiles walks a directory and returns files matching include/exclude patterns.
func collectFiles(dir string, include, exclude []string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		name := filepath.Base(path)

		// Apply exclude patterns first.
		for _, pat := range exclude {
			matched, _ := filepath.Match(pat, name)
			if matched {
				return nil
			}
			// Also try matching against relative path.
			matched, _ = filepath.Match(pat, relPath)
			if matched {
				return nil
			}
		}

		// Apply include patterns (if any).
		if len(include) > 0 {
			matched := false
			for _, pat := range include {
				m, _ := filepath.Match(pat, name)
				if m {
					matched = true
					break
				}
				m, _ = filepath.Match(pat, relPath)
				if m {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})
	return files, err
}

// collectVpackFiles walks a directory for .vpack files.
func collectVpackFiles(dir string) ([]string, error) {
	return collectFiles(dir, []string{"*.vpack"}, nil)
}

// buildBatchEntries maps source files to output files, preserving directory structure.
func buildBatchEntries(files []string, srcDir, outDir, suffix string) []BatchFileEntry {
	entries := make([]BatchFileEntry, 0, len(files))
	for _, f := range files {
		relPath, _ := filepath.Rel(srcDir, f)
		outPath := filepath.Join(outDir, relPath+suffix)
		entries = append(entries, BatchFileEntry{
			InputPath:  f,
			OutputPath: outPath,
			RelPath:    relPath,
		})
	}
	return entries
}

// buildBatchDecryptEntries maps .vpack files to output files, stripping the .vpack extension.
func buildBatchDecryptEntries(files []string, srcDir, outDir string) []BatchFileEntry {
	entries := make([]BatchFileEntry, 0, len(files))
	for _, f := range files {
		relPath, _ := filepath.Rel(srcDir, f)
		outName := strings.TrimSuffix(relPath, ".vpack")
		outPath := filepath.Join(outDir, outName)
		entries = append(entries, BatchFileEntry{
			InputPath:  f,
			OutputPath: outPath,
			RelPath:    relPath,
		})
	}
	return entries
}

// processFn is the function signature for processing one file in a batch.
type processFn func(entry BatchFileEntry) error

// runParallel processes entries concurrently with up to `workers` goroutines.
// It returns results for every entry. Errors are collected but do not abort the batch.
func runParallel(entries []BatchFileEntry, workers int, fn processFn, printer *Printer) []BatchResult {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(entries) {
		workers = len(entries)
	}

	results := make([]BatchResult, len(entries))
	ch := make(chan int, len(entries))
	for i := range entries {
		ch <- i
	}
	close(ch)

	var succeeded, failed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range ch {
				entry := entries[idx]
				start := time.Now()
				err := fn(entry)
				dur := time.Since(start)

				r := BatchResult{
					RelPath:    entry.RelPath,
					InputPath:  entry.InputPath,
					OutputPath: entry.OutputPath,
					Duration:   dur.Round(time.Millisecond).String(),
				}
				if err != nil {
					r.Status = "error"
					r.Error = err.Error()
					failed.Add(1)
				} else {
					r.Status = "ok"
					succeeded.Add(1)
				}
				results[idx] = r
			}
		}()
	}

	wg.Wait()
	return results
}

// writeBatchManifest writes the batch-manifest.json to outDir.
func writeBatchManifest(outDir string, bm *BatchManifest) error {
	path := filepath.Join(outDir, "batch-manifest.json")
	data, err := json.MarshalIndent(bm, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal batch manifest: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// ensureParentDir creates the parent directory for a file path.
func ensureParentDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0o755)
}
