package cli

import (
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/transparency"
)

// mockRekorServer is a test-only Rekor that signs SETs with a freshly-generated
// ECDSA key. The PEM-encoded public key is exposed via /api/v1/log/publicKey.
type mockRekorServer struct {
	*httptest.Server
	logKey *ecdsa.PrivateKey
	pubPEM []byte
	logID  string

	mu        sync.Mutex
	stored    map[string][]byte
	nextIndex int64
}

func newMockRekorServer(t *testing.T) *mockRekorServer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	idSum := sha256.Sum256(pubDER)
	m := &mockRekorServer{
		logKey: priv,
		pubPEM: pubPEM,
		logID:  hex.EncodeToString(idSum[:]),
		stored: map[string][]byte{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/log/publicKey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(m.pubPEM)
	})
	mux.HandleFunc("/api/v1/log/entries", m.handleEntries)
	mux.HandleFunc("/api/v1/log/entries/", m.handleEntryByUUID)
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Server.Close)
	return m
}

func (m *mockRekorServer) handleEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var entry transparency.HashedRekordEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(entry)
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	m.mu.Lock()
	m.nextIndex++
	idx := m.nextIndex
	m.mu.Unlock()
	ts := int64(1700000000 + idx)
	canon := canonicalSETForTests(bodyB64, ts, m.logID, idx)
	sum := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, m.logKey, sum[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	anon := transparency.LogEntryAnon{
		Body:           bodyB64,
		IntegratedTime: ts,
		LogID:          m.logID,
		LogIndex:       idx,
		Verification: &transparency.LogEntryVerifData{
			SignedEntryTimestamp: base64.StdEncoding.EncodeToString(sig),
		},
	}
	uuidSum := sha256.Sum256(body)
	uuid := hex.EncodeToString(uuidSum[:])
	resp := map[string]transparency.LogEntryAnon{uuid: anon}
	respBytes, _ := json.Marshal(resp)
	m.mu.Lock()
	m.stored[uuid] = respBytes
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(respBytes)
}

func (m *mockRekorServer) handleEntryByUUID(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
	m.mu.Lock()
	raw, ok := m.stored[uuid]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// canonicalSETForTests mirrors transparency.canonicalSETPayload (unexported).
func canonicalSETForTests(body string, integratedTime int64, logID string, logIndex int64) []byte {
	type canon struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}
	b, _ := json.Marshal(canon{body, integratedTime, logID, logIndex})
	return b
}

// makeEd25519KeyFiles generates a fresh ed25519 keypair as PEM files for
// sign/verify tests. The keygen subcommand writes the public key next to the
// private one, swapping the `.key` extension for `.pub`.
func makeEd25519KeyFiles(t *testing.T, dir string) (priv, pub string) {
	t.Helper()
	cmd := NewRootCmd()
	keyFile := filepath.Join(dir, "id.key")
	cmd.SetArgs([]string{"keygen", "--out", keyFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return keyFile, filepath.Join(dir, "id.pub")
}

// TestSignTransparency_RoundTrip exercises the full sign+verify pipeline with
// a mock Rekor: protect → sign --transparency → verify --check-transparency
// must succeed end-to-end, and the manifest must carry a Transparency entry.
func TestSignTransparency_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	dataKey := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(in, []byte("transparency-roundtrip"), 0o600); err != nil {
		t.Fatal(err)
	}

	rekor := newMockRekorServer(t)
	pubPEMFile := filepath.Join(dir, "rekor-pub.pem")
	if err := os.WriteFile(pubPEMFile, rekor.pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	priv, pub := makeEd25519KeyFiles(t, dir)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", dataKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"sign", "--in", bundleFile,
		"--signing-priv", priv,
		"--transparency",
		"--rekor-url", rekor.URL,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign --transparency: %v", err)
	}

	// Manifest must now contain a Transparency entry pointing at the mock.
	br, err := bundle.Read(bundleFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := len(br.Manifest.Transparency); got != 1 {
		t.Fatalf("expected 1 transparency entry, got %d", got)
	}
	if br.Manifest.Transparency[0].LogURL != rekor.URL {
		t.Errorf("log_url mismatch: %s", br.Manifest.Transparency[0].LogURL)
	}
	if br.Manifest.Transparency[0].UUID == "" {
		t.Error("uuid empty")
	}

	// Verify with transparency check against the mock's pubkey.
	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"verify", "--in", bundleFile, "--pubkey", pub,
		"--check-transparency",
		"--rekor-pubkey", pubPEMFile,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify --check-transparency: %v", err)
	}
}

// TestVerify_TransparencyMismatchFails: tampering with the manifest's stored
// SETB64 must cause verify --check-transparency to fail.
func TestVerify_TransparencyMismatchFails(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	dataKey := filepath.Join(dir, "secret.key")
	os.WriteFile(in, []byte("transparency-tamper"), 0o600)

	rekor := newMockRekorServer(t)
	pubPEMFile := filepath.Join(dir, "rekor-pub.pem")
	os.WriteFile(pubPEMFile, rekor.pubPEM, 0o600)

	priv, pub := makeEd25519KeyFiles(t, dir)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", dataKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}
	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"sign", "--in", bundleFile, "--signing-priv", priv,
		"--transparency", "--rekor-url", rekor.URL,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper: swap the SET with a different base64-encoded value of the same length.
	br, err := bundle.Read(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	orig := br.Manifest.Transparency[0].SETB64
	rawSig, _ := base64.StdEncoding.DecodeString(orig)
	rawSig[0] ^= 0xFF
	br.Manifest.Transparency[0].SETB64 = base64.StdEncoding.EncodeToString(rawSig)

	// Re-write the bundle with the modified manifest.
	mBytes, _ := bundle.MarshalManifest(br.Manifest)
	if err := bundle.Write(&bundle.WriteParams{
		OutputPath:    bundleFile,
		Ciphertext:    br.Ciphertext,
		ManifestBytes: mBytes,
		Signature:     br.Signature,
	}); err != nil {
		t.Fatal(err)
	}

	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"verify", "--in", bundleFile, "--pubkey", pub,
		"--check-transparency", "--rekor-pubkey", pubPEMFile,
	})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected verify to fail with tampered SET")
	}
	if !strings.Contains(err.Error(), "SET signature invalid") && !strings.Contains(err.Error(), "transparency entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSign_TransparencyRejectsPQAlgo: ml-dsa/slh-dsa signing keys must be
// rejected when --transparency is requested, because Rekor cannot verify them.
func TestSign_TransparencyRejectsPQAlgo(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "secret.txt")
	bundleFile := filepath.Join(dir, "secret.vpack")
	dataKey := filepath.Join(dir, "secret.key")
	os.WriteFile(in, []byte("pq-rekor-reject"), 0o600)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"protect", "--in", in, "--out", bundleFile, "--key-out", dataKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("protect: %v", err)
	}

	priv := filepath.Join(dir, "pq.key")
	cmd = NewRootCmd()
	cmd.SetArgs([]string{"keygen", "--algo", "ml-dsa-65", "--out", priv})
	if err := cmd.Execute(); err != nil {
		t.Skipf("ml-dsa-65 keygen not available: %v", err)
	}

	cmd = NewRootCmd()
	cmd.SetArgs([]string{
		"sign", "--in", bundleFile, "--signing-priv", priv,
		"--transparency", "--rekor-url", "http://127.0.0.1:1", // never reached
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected sign to reject ml-dsa with --transparency")
	}
	if !strings.Contains(err.Error(), "Rekor-compatible") {
		t.Errorf("unexpected error: %v", err)
	}
}
