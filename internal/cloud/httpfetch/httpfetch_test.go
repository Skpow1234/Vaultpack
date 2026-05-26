package httpfetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/cloud"
)

func TestDownload(t *testing.T) {
	want := []byte("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	s := NewStore(Options{})
	got, err := s.Download(context.Background(), srv.URL+"/bundle.vpack")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("download body = %q, want %q", got, want)
	}
}

func TestDownloadToWriter(t *testing.T) {
	want := []byte("streamed payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	s := NewStore(Options{})
	var buf bytes.Buffer
	if err := s.DownloadToWriter(context.Background(), srv.URL+"/x", &buf); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("stream body = %q, want %q", buf.String(), string(want))
	}
}

func TestDownload_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := NewStore(Options{})
	if _, err := s.Download(context.Background(), srv.URL+"/missing"); err == nil {
		t.Error("expected error on 404")
	}
}

func TestBearerAuth(t *testing.T) {
	t.Setenv("VAULTPACK_HTTP_BEARER", "secret-token-123")
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := NewStore(Options{})
	if _, err := s.Download(context.Background(), srv.URL); err != nil {
		t.Fatalf("download: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || !strings.Contains(gotAuth, "secret-token-123") {
		t.Errorf("Authorization header = %q, want Bearer secret-token-123", gotAuth)
	}
}

func TestBasicAuth(t *testing.T) {
	t.Setenv("VAULTPACK_HTTP_BEARER", "")
	t.Setenv("VAULTPACK_HTTP_USER", "alice")
	t.Setenv("VAULTPACK_HTTP_PASS", "wonderland")
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := NewStore(Options{})
	if _, err := s.Download(context.Background(), srv.URL); err != nil {
		t.Fatalf("download: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("Authorization header = %q, want Basic ...", gotAuth)
	}
}

func TestUploadReadOnly(t *testing.T) {
	s := NewStore(Options{})
	err := s.Upload(context.Background(), "https://example.com/x", strings.NewReader("x"), 1)
	if !errors.Is(err, cloud.ErrReadOnly) {
		t.Errorf("Upload err = %v, want ErrReadOnly", err)
	}
}

func TestListNotSupported(t *testing.T) {
	s := NewStore(Options{})
	_, err := s.List(context.Background(), "https://example.com/")
	if !errors.Is(err, cloud.ErrNotSupported) {
		t.Errorf("List err = %v, want ErrNotSupported", err)
	}
}
