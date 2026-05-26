package transparency

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockRekor is an in-process HTTP server that mimics enough of Rekor's API for
// VaultPack's tests: POST /api/v1/log/entries returns a synthetic LogEntryAnon
// with a Signed Entry Timestamp produced by a freshly-generated ECDSA key.
// GET /api/v1/log/publicKey returns that key's PEM.
type mockRekor struct {
	srv    *httptest.Server
	logKey *ecdsa.PrivateKey
	pubPEM []byte
	logID  string
	// stored maps UUID → response so Fetch works.
	stored map[string][]byte
	// nextIndex increments on each upload.
	nextIndex int64
}

func newMockRekor(t *testing.T) *mockRekor {
	t.Helper()
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	logIDSum := sha256.Sum256(pubDER)
	logID := hex.EncodeToString(logIDSum[:])
	m := &mockRekor{logKey: logKey, pubPEM: pubPEM, logID: logID, stored: map[string][]byte{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/log/publicKey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(m.pubPEM)
	})
	mux.HandleFunc("/api/v1/log/entries", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var entry HashedRekordEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(entry)
		bodyB64 := base64.StdEncoding.EncodeToString(body)
		m.nextIndex++
		idx := m.nextIndex
		ts := int64(1700000000 + idx)
		canonical := mustCanonicalSET(bodyB64, ts, m.logID, idx)
		sum := sha256.Sum256(canonical)
		sig, err := ecdsa.SignASN1(rand.Reader, m.logKey, sum[:])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		anon := LogEntryAnon{
			Body:           bodyB64,
			IntegratedTime: ts,
			LogID:          m.logID,
			LogIndex:       idx,
			Verification: &LogEntryVerifData{
				SignedEntryTimestamp: base64.StdEncoding.EncodeToString(sig),
			},
		}
		uuid := hex.EncodeToString(sha256.New().Sum([]byte("uuid-")))[:32]
		resp := map[string]LogEntryAnon{uuid: anon}
		respBytes, _ := json.Marshal(resp)
		m.stored[uuid] = respBytes
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(respBytes)
	})
	mux.HandleFunc("/api/v1/log/entries/", func(w http.ResponseWriter, r *http.Request) {
		uuid := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
		raw, ok := m.stored[uuid]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func mustCanonicalSET(body string, integratedTime int64, logID string, logIndex int64) []byte {
	b, err := canonicalSETPayload(body, integratedTime, logID, logIndex)
	if err != nil {
		panic(err)
	}
	return b
}

func (m *mockRekor) URL() string { return m.srv.URL }

// --- tests ---

func TestRekor_Upload_RoundTrip(t *testing.T) {
	mr := newMockRekor(t)
	client := NewRekorClient(mr.URL())

	pubPEM := []byte("---- PEM ----")
	sig := []byte("signature-bytes")
	data := []byte("the data that was signed")

	entry := BuildHashedRekord(pubPEM, sig, data)
	uuid, anon, err := client.Upload(context.Background(), entry)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if uuid == "" {
		t.Fatal("uuid empty")
	}
	if anon.LogIndex == 0 {
		t.Fatal("log index empty")
	}
	if anon.Verification == nil || anon.Verification.SignedEntryTimestamp == "" {
		t.Fatal("missing SET")
	}

	// Verify SET round-trip.
	if err := VerifySET(VerifyParams{
		RekorPubPEM:    mr.pubPEM,
		LogID:          mr.logID,
		LogIndex:       anon.LogIndex,
		IntegratedTime: anon.IntegratedTime,
		Body:           anon.Body,
		SETB64:         anon.Verification.SignedEntryTimestamp,
	}); err != nil {
		t.Errorf("SET verify failed: %v", err)
	}

	// Tampering with the body must invalidate the SET.
	bogus := anon.Body + "AAAA"
	if err := VerifySET(VerifyParams{
		RekorPubPEM:    mr.pubPEM,
		LogID:          mr.logID,
		LogIndex:       anon.LogIndex,
		IntegratedTime: anon.IntegratedTime,
		Body:           bogus,
		SETB64:         anon.Verification.SignedEntryTimestamp,
	}); err == nil {
		t.Error("tampered body should not verify")
	}

	// Fetch should return the same record.
	fetched, err := client.Fetch(context.Background(), uuid)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if fetched.LogIndex != anon.LogIndex {
		t.Errorf("fetched index mismatch")
	}
}

func TestRekor_PublicKey(t *testing.T) {
	mr := newMockRekor(t)
	client := NewRekorClient(mr.URL())
	got, err := client.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "PUBLIC KEY") {
		t.Errorf("expected PEM, got: %s", got)
	}
}

func TestBuildHashedRekord_HashesData(t *testing.T) {
	data := []byte("hello-rekor")
	entry := BuildHashedRekord([]byte("pub"), []byte("sig"), data)
	want := sha256.Sum256(data)
	if entry.Spec.Data.Hash.Value != hex.EncodeToString(want[:]) {
		t.Errorf("hash mismatch: got %s", entry.Spec.Data.Hash.Value)
	}
	if entry.Kind != KindHashedRekord {
		t.Errorf("kind mismatch: %s", entry.Kind)
	}
	if entry.APIVersion != APIVersionV001 {
		t.Errorf("api version mismatch: %s", entry.APIVersion)
	}
}

func TestParseOIDCClaims(t *testing.T) {
	// Hand-craft a JWT with email + iss claims.
	claims := map[string]any{
		"iss":   "https://issuer.example",
		"sub":   "user-123",
		"email": "alice@example.com",
	}
	body, _ := json.Marshal(claims)
	jwt := "ignored." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	c, err := ParseOIDCClaims(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "alice@example.com" {
		t.Errorf("email: %s", c.Email)
	}
	if c.Issuer != "https://issuer.example" {
		t.Errorf("iss: %s", c.Issuer)
	}
	if SubjectFromClaims(c) != "alice@example.com" {
		t.Error("subject should default to email")
	}
}
