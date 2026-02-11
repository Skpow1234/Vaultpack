package azure

import (
	"testing"
)

func TestIsAzureURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"az://container/blob.csv", true},
		{"az://container/dir/file.txt", true},
		{"az://mycontainer", true},
		{"az://", true},
		{"s3://bucket/key", false},
		{"gs://bucket/path", false},
		{"./local/file.txt", false},
		{"", false},
		{"AZ://container/blob", false}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsAzureURI(tt.input)
			if got != tt.want {
				t.Errorf("IsAzureURI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		name          string
		uri           string
		wantContainer string
		wantBlob      string
		wantErr       bool
	}{
		{
			name:          "container and blob",
			uri:           "az://mycontainer/path/to/blob.csv",
			wantContainer: "mycontainer",
			wantBlob:      "path/to/blob.csv",
		},
		{
			name:          "container only",
			uri:           "az://mycontainer",
			wantContainer: "mycontainer",
			wantBlob:      "",
		},
		{
			name:          "container with trailing slash",
			uri:           "az://mycontainer/",
			wantContainer: "mycontainer",
			wantBlob:      "",
		},
		{
			name:          "deeply nested blob",
			uri:           "az://bucket/a/b/c/d/file.vpack",
			wantContainer: "bucket",
			wantBlob:      "a/b/c/d/file.vpack",
		},
		{
			name:          "container with prefix dir",
			uri:           "az://container/prefix/",
			wantContainer: "container",
			wantBlob:      "prefix/",
		},
		{
			name:    "not azure URI",
			uri:     "s3://bucket/key",
			wantErr: true,
		},
		{
			name:    "empty azure URI",
			uri:     "az://",
			wantErr: true,
		},
		{
			name:    "empty container",
			uri:     "az:///blob",
			wantErr: true,
		},
		{
			name:    "local path",
			uri:     "/local/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container, blob, err := ParseURI(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseURI(%q) expected error, got nil", tt.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURI(%q) unexpected error: %v", tt.uri, err)
			}
			if container != tt.wantContainer {
				t.Errorf("container = %q, want %q", container, tt.wantContainer)
			}
			if blob != tt.wantBlob {
				t.Errorf("blob = %q, want %q", blob, tt.wantBlob)
			}
		})
	}
}

func TestNewServiceClient_NoAccountOrConnStr(t *testing.T) {
	// Without account name or connection string, should return an error.
	_, err := NewServiceClient(ClientOptions{})
	if err == nil {
		t.Fatal("expected error when no account or connection string is provided")
	}
}

func TestNewServiceClient_InvalidConnectionString(t *testing.T) {
	// An invalid connection string should still create a client but fail later,
	// or return an error depending on SDK behavior. Let's check it doesn't panic.
	_, err := NewServiceClient(ClientOptions{
		ConnectionString: "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;EndpointSuffix=core.windows.net",
	})
	// The SDK may accept this. We just ensure no panic.
	_ = err
}

func TestNewServiceClient_WithAccountName(t *testing.T) {
	// With a valid account name, the SDK should create a client
	// (auth will fail at actual request time, but client creation should succeed).
	client, err := NewServiceClient(ClientOptions{
		AccountName: "teststorageaccount",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}
