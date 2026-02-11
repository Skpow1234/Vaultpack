package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAzureHelper(t *testing.T) {
	if !isAzure("az://container/blob") {
		t.Error("expected az:// to be detected as Azure")
	}
	if isAzure("./local/path") {
		t.Error("expected local path to not be detected as Azure")
	}
	if isAzure("s3://bucket/key") {
		t.Error("expected s3:// to not be detected as Azure")
	}
}

func TestProtectCmd_AzureInputRequiresConfig(t *testing.T) {
	// When --in is az:// but no Azure config, should get an Azure-related error.
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "out.vpack")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect",
		"--in", "az://testcontainer/testblob.csv",
		"--out", outFile,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using az:// without Azure config")
	}
	// The error should mention Azure or download.
	errStr := err.Error()
	if !contains(errStr, "Azure") && !contains(errStr, "azure") && !contains(errStr, "AZURE") {
		t.Errorf("error should mention Azure, got: %s", errStr)
	}
}

func TestDecryptCmd_AzureInputRequiresConfig(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "out.txt")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"decrypt",
		"--in", "az://testcontainer/testblob.vpack",
		"--out", outFile,
		"--key", "dummy.key",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using az:// without Azure config")
	}
}

func TestInspectCmd_AzureInputRequiresConfig(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"inspect",
		"--in", "az://testcontainer/testblob.vpack",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using az:// without Azure config")
	}
}

func TestBatchProtectCmd_AzureSourceRequiresConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"batch-protect",
		"--dir", "az://testcontainer/data/",
		"--out-dir", tmpDir,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using az:// without Azure config")
	}
}

func TestBatchDecryptCmd_AzureSourceRequiresConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"batch-decrypt",
		"--dir", "az://testcontainer/encrypted/",
		"--out-dir", tmpDir,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using az:// without Azure config")
	}
}

func TestProtectDecrypt_LocalRoundTrip_Unaffected(t *testing.T) {
	// Verify that local (non-Azure) protect/decrypt still works fine.
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	bundleFile := filepath.Join(tmpDir, "test.vpack")
	keyFile := filepath.Join(tmpDir, "test.key")
	outputFile := filepath.Join(tmpDir, "test_decrypted.txt")

	content := "Hello, VaultPack with Azure integration!"
	if err := os.WriteFile(inputFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Protect.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"protect",
		"--in", inputFile,
		"--out", bundleFile,
		"--key-out", keyFile,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect failed: %v", err)
	}
	if _, err := os.Stat(bundleFile); err != nil {
		t.Fatalf("bundle not created: %v", err)
	}

	// Decrypt.
	cmd2 := NewRootCmd()
	cmd2.SetArgs([]string{
		"decrypt",
		"--in", bundleFile,
		"--out", outputFile,
		"--key", keyFile,
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Verify.
	decrypted, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != content {
		t.Errorf("content mismatch: got %q, want %q", string(decrypted), content)
	}
}

func TestAzureGlobalFlags_Registered(t *testing.T) {
	cmd := NewRootCmd()

	// Check that Azure flags are registered as persistent flags.
	f := cmd.PersistentFlags().Lookup("azure-account")
	if f == nil {
		t.Error("--azure-account flag not registered")
	}
	f = cmd.PersistentFlags().Lookup("azure-connection-string")
	if f == nil {
		t.Error("--azure-connection-string flag not registered")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
