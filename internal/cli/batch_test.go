package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- helpers ---

func createTestDir(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// --- batch-protect → batch-decrypt round-trip ---

func TestBatchProtectDecrypt_SharedKey(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")
	decDir := filepath.Join(t.TempDir(), "dec")

	files := map[string]string{
		"a.txt":           "alpha content",
		"b.txt":           "bravo content",
		"sub/c.txt":       "charlie in sub dir",
		"sub/deep/d.txt":  "delta deep nested",
	}
	createTestDir(t, srcDir, files)

	// Batch protect.
	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect",
		"--dir", srcDir,
		"--out-dir", encDir,
		"--workers", "2",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect: %v", err)
	}

	// Verify .vpack files exist.
	for name := range files {
		vpackPath := filepath.Join(encDir, name+".vpack")
		if _, err := os.Stat(vpackPath); err != nil {
			t.Errorf("missing bundle: %s", vpackPath)
		}
	}

	// Verify batch.key exists.
	batchKey := filepath.Join(encDir, "batch.key")
	if _, err := os.Stat(batchKey); err != nil {
		t.Fatalf("batch.key not found")
	}

	// Verify batch-manifest.json exists and is valid.
	bmPath := filepath.Join(encDir, "batch-manifest.json")
	bmData, err := os.ReadFile(bmPath)
	if err != nil {
		t.Fatalf("read batch manifest: %v", err)
	}
	var bm BatchManifest
	if err := json.Unmarshal(bmData, &bm); err != nil {
		t.Fatalf("parse batch manifest: %v", err)
	}
	if bm.Total != 4 {
		t.Errorf("expected 4 total, got %d", bm.Total)
	}
	if bm.Succeeded != 4 {
		t.Errorf("expected 4 succeeded, got %d", bm.Succeeded)
	}
	if bm.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", bm.Failed)
	}

	// Batch decrypt.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-decrypt",
		"--dir", encDir,
		"--out-dir", decDir,
		"--key", batchKey,
		"--workers", "2",
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("batch-decrypt: %v", err)
	}

	// Verify decrypted content.
	for name, expected := range files {
		decPath := filepath.Join(decDir, name)
		got, err := os.ReadFile(decPath)
		if err != nil {
			t.Errorf("read decrypted %s: %v", name, err)
			continue
		}
		if string(got) != expected {
			t.Errorf("%s: got %q, want %q", name, got, expected)
		}
	}
}

func TestBatchProtectDecrypt_PerFileKey(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")
	decDir := filepath.Join(t.TempDir(), "dec")

	files := map[string]string{
		"x.txt": "x-data",
		"y.txt": "y-data",
	}
	createTestDir(t, srcDir, files)

	// Batch protect with per-file key.
	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect",
		"--dir", srcDir,
		"--out-dir", encDir,
		"--per-file-key",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect: %v", err)
	}

	// Verify per-file .key files exist.
	for name := range files {
		keyPath := filepath.Join(encDir, name+".vpack.key")
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("missing per-file key: %s", keyPath)
		}
	}

	// Batch decrypt (auto-detect per-file keys).
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-decrypt",
		"--dir", encDir,
		"--out-dir", decDir,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("batch-decrypt: %v", err)
	}

	for name, expected := range files {
		got, err := os.ReadFile(filepath.Join(decDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != expected {
			t.Errorf("%s: got %q, want %q", name, got, expected)
		}
	}
}

func TestBatchProtect_WithCompression(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")
	decDir := filepath.Join(t.TempDir(), "dec")

	// Create a repetitive file to benefit from compression.
	big := bytes.Repeat([]byte("AAAA"), 1000)
	createTestDir(t, srcDir, map[string]string{
		"big.txt": string(big),
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir, "--compress", "gzip",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect with compress: %v", err)
	}

	batchKey := filepath.Join(encDir, "batch.key")

	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-decrypt", "--dir", encDir, "--out-dir", decDir, "--key", batchKey,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("batch-decrypt: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(decDir, "big.txt"))
	if !bytes.Equal(got, big) {
		t.Fatal("decompressed content mismatch")
	}
}

func TestBatchProtect_IncludeExclude(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")

	createTestDir(t, srcDir, map[string]string{
		"data.csv": "csv data",
		"data.log": "log data",
		"note.txt": "text data",
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir,
		"--include", "*.csv",
		"--include", "*.txt",
		"--exclude", "*.log",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect: %v", err)
	}

	// CSV and TXT should be protected; LOG should not.
	if _, err := os.Stat(filepath.Join(encDir, "data.csv.vpack")); err != nil {
		t.Error("data.csv.vpack should exist")
	}
	if _, err := os.Stat(filepath.Join(encDir, "note.txt.vpack")); err != nil {
		t.Error("note.txt.vpack should exist")
	}
	if _, err := os.Stat(filepath.Join(encDir, "data.log.vpack")); err == nil {
		t.Error("data.log.vpack should NOT exist")
	}
}

func TestBatchProtect_DryRun(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")

	createTestDir(t, srcDir, map[string]string{
		"a.txt": "alpha",
		"b.txt": "bravo",
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir, "--dry-run",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect dry-run: %v", err)
	}

	// No files should actually be created.
	if _, err := os.Stat(encDir); err == nil {
		entries, _ := os.ReadDir(encDir)
		if len(entries) > 0 {
			t.Error("dry-run should not create any output files")
		}
	}
}

func TestBatchProtect_DryRunJSON(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")

	createTestDir(t, srcDir, map[string]string{
		"a.txt": "alpha",
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir, "--dry-run", "--json",
	})

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root.Execute()
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("dry-run json: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse json: %v\nraw: %s", err, buf.String())
	}
	if result["dry_run"] != true {
		t.Error("expected dry_run: true")
	}
}

func TestBatchProtect_EmptyDir(t *testing.T) {
	srcDir := t.TempDir()
	encDir := filepath.Join(t.TempDir(), "enc")

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir,
	})
	// Should not error, just print "no files found".
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect empty: %v", err)
	}
}

func TestBatchDecrypt_ErrorOnBadKey(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")
	decDir := filepath.Join(t.TempDir(), "dec")

	createTestDir(t, srcDir, map[string]string{
		"a.txt": "alpha",
	})

	// Protect.
	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir,
	})
	root.Execute()

	// Create a wrong key.
	wrongKey := filepath.Join(t.TempDir(), "wrong.key")
	os.WriteFile(wrongKey, []byte("b64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o600)

	// Decrypt with wrong key should fail.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-decrypt", "--dir", encDir, "--out-dir", decDir, "--key", wrongKey,
	})
	err := root2.Execute()
	if err == nil {
		t.Fatal("expected error for wrong key")
	}

	// Batch manifest should still be written with failure info.
	bmData, _ := os.ReadFile(filepath.Join(decDir, "batch-manifest.json"))
	var bm BatchManifest
	json.Unmarshal(bmData, &bm)
	if bm.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", bm.Failed)
	}
}

func TestBatchInspect(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")

	createTestDir(t, srcDir, map[string]string{
		"a.txt": "alpha",
		"b.txt": "bravo",
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir,
	})
	root.Execute()

	// Inspect.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-inspect", "--dir", encDir,
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("batch-inspect: %v", err)
	}
}

func TestBatchInspect_JSON(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")

	createTestDir(t, srcDir, map[string]string{
		"a.txt": "alpha",
	})

	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir,
	})
	root.Execute()

	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-inspect", "--dir", encDir, "--json",
	})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root2.Execute()
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("batch-inspect json: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse json: %v", err)
	}

	if result["total"].(float64) != 1 {
		t.Errorf("expected 1 bundle, got %v", result["total"])
	}
}

func TestBatchProtect_ParallelCorrectness(t *testing.T) {
	// Test with many files to exercise parallelism.
	srcDir := filepath.Join(t.TempDir(), "src")
	encDir := filepath.Join(t.TempDir(), "enc")
	decDir := filepath.Join(t.TempDir(), "dec")

	files := make(map[string]string)
	for i := 0; i < 20; i++ {
		name := filepath.Join("dir"+string(rune('a'+i%5)), "file"+intToStr(i)+".txt")
		files[name] = "content-" + intToStr(i)
	}
	createTestDir(t, srcDir, files)

	// Protect with 4 workers.
	root := NewRootCmd()
	root.SetArgs([]string{
		"batch-protect", "--dir", srcDir, "--out-dir", encDir, "--workers", "4",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("batch-protect: %v", err)
	}

	batchKey := filepath.Join(encDir, "batch.key")

	// Decrypt with 4 workers.
	root2 := NewRootCmd()
	root2.SetArgs([]string{
		"batch-decrypt", "--dir", encDir, "--out-dir", decDir, "--key", batchKey, "--workers", "4",
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("batch-decrypt: %v", err)
	}

	// Verify all files.
	for name, expected := range files {
		got, err := os.ReadFile(filepath.Join(decDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != expected {
			t.Errorf("%s: got %q, want %q", name, got, expected)
		}
	}
}
