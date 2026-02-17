package kms

import (
	"testing"
)

func TestParseAzureKeyID(t *testing.T) {
	tests := []struct {
		keyID     string
		wantVault string
		wantName  string
		wantVer   string
		wantErr   bool
	}{
		{
			"https://myvault.vault.azure.net/keys/mykey/abc123",
			"https://myvault.vault.azure.net",
			"mykey",
			"abc123",
			false,
		},
		{
			"https://myvault.vault.azure.net/keys/mykey",
			"https://myvault.vault.azure.net",
			"mykey",
			"",
			false,
		},
		{"https://other.net/keys/k", "", "", "", true},
		{"not-a-url", "", "", "", true},
		{"https://myvault.vault.azure.net/", "", "", "", true},
	}
	for _, tt := range tests {
		vault, name, ver, err := ParseAzureKeyID(tt.keyID)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseAzureKeyID(%q) err = %v, wantErr %v", tt.keyID, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if vault != tt.wantVault || name != tt.wantName || ver != tt.wantVer {
				t.Errorf("ParseAzureKeyID(%q) = %q, %q, %q; want %q, %q, %q",
					tt.keyID, vault, name, ver, tt.wantVault, tt.wantName, tt.wantVer)
			}
		}
	}
}
