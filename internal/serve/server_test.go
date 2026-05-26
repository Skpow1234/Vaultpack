package serve_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/serve"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// startServer spins up a Server bound to a random localhost TCP port and
// returns its base URL (http://127.0.0.1:NNNN) plus a cancel function.
func startServer(t *testing.T, opts serve.Options) (string, func()) {
	t.Helper()
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := serve.NewServer(opts)
	if err != nil {
		ln.Close()
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx, ln)
	}()
	base := "http://" + ln.Addr().String()

	// Wait for /healthz to come up (max 2s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}

	return base, func() {
		cancel()
		shutdownCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		_ = srv.Shutdown(shutdownCtx)
	}
}

func postJSON(t *testing.T, url, token string, body any) map[string]any {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("POST %s: invalid JSON reply (status=%d): %v: %s", url, resp.StatusCode, err, raw)
	}
	out["_status"] = resp.StatusCode
	return out
}

// --- tests ---

func TestNewServer_RefusesWithoutAuth(t *testing.T) {
	_, err := serve.NewServer(serve.Options{Listen: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("expected NewServer to refuse without auth")
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("error message changed: %v", err)
	}
}

func TestHealthAndVersion(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()

	// /healthz: no auth needed.
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz status = %d", resp.StatusCode)
	}

	// /v1/version: GET.
	resp2, err := http.Get(base + "/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	if v["ok"] != true {
		t.Errorf("version reply: %s", body)
	}
	if v["sdk_version"] == "" {
		t.Error("missing sdk_version")
	}
}

func TestAuth_Bearer(t *testing.T) {
	const token = "topsecret-token-1234"
	base, stop := startServer(t, serve.Options{AuthToken: token})
	defer stop()

	// Missing token -> 401.
	resp, err := http.Get(base + "/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 without bearer, got %d", resp.StatusCode)
	}

	// Wrong token -> 401.
	req, _ := http.NewRequest("GET", base+"/v1/version", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Errorf("expected 401 with wrong bearer, got %d", resp2.StatusCode)
	}

	// Right token -> 200.
	req3, _ := http.NewRequest("GET", base+"/v1/version", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Errorf("expected 200 with right bearer, got %d", resp3.StatusCode)
	}
}

func TestProtectDecrypt_RoundTrip_InMemory(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()

	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	// Protect: in-memory plaintext, no output path -> bundle returned in reply.
	enc := postJSON(t, base+"/v1/protect", "", map[string]any{
		"plaintext_b64": util.B64Encode(plaintext),
		"input_name":    "fox.txt",
		"cipher":        "chacha20-poly1305",
	})
	if enc["ok"] != true {
		t.Fatalf("protect failed: %v", enc)
	}
	bundleB64, _ := enc["bundle_b64"].(string)
	keyB64, _ := enc["generated_key_b64"].(string)
	if bundleB64 == "" || keyB64 == "" {
		t.Fatalf("protect reply missing bundle/key: %+v", enc)
	}

	// Decrypt the same bundle.
	dec := postJSON(t, base+"/v1/decrypt", "", map[string]any{
		"bundle_b64": bundleB64,
		"key_b64":    keyB64,
	})
	if dec["ok"] != true {
		t.Fatalf("decrypt failed: %v", dec)
	}
	gotB64, _ := dec["plaintext_b64"].(string)
	got, err := util.B64Decode(gotB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestProtectDecrypt_Password(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()

	enc := postJSON(t, base+"/v1/protect", "", map[string]any{
		"plaintext_b64": util.B64Encode([]byte("secret data")),
		"password":      "correct horse battery staple",
	})
	if enc["ok"] != true {
		t.Fatalf("protect failed: %v", enc)
	}
	bundleB64, _ := enc["bundle_b64"].(string)

	// Right password.
	dec := postJSON(t, base+"/v1/decrypt", "", map[string]any{
		"bundle_b64": bundleB64,
		"password":   "correct horse battery staple",
	})
	if dec["ok"] != true {
		t.Fatalf("decrypt failed: %v", dec)
	}

	// Wrong password.
	bad := postJSON(t, base+"/v1/decrypt", "", map[string]any{
		"bundle_b64": bundleB64,
		"password":   "wrong",
	})
	if bad["ok"] != false {
		t.Fatalf("expected wrong-password failure: %v", bad)
	}
}

func TestInspect_BundleB64(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()
	enc := postJSON(t, base+"/v1/protect", "", map[string]any{
		"plaintext_b64": util.B64Encode([]byte("x")),
		"input_name":    "inspect.txt",
	})
	bundleB64, _ := enc["bundle_b64"].(string)

	ins := postJSON(t, base+"/v1/inspect", "", map[string]any{
		"bundle_b64": bundleB64,
	})
	if ins["ok"] != true {
		t.Fatalf("inspect failed: %v", ins)
	}
	m, _ := ins["manifest"].(map[string]any)
	input, _ := m["input"].(map[string]any)
	if input["name"] != "inspect.txt" {
		t.Errorf("input.name = %v", input["name"])
	}
}

func TestSignVerify_BundleB64(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()

	enc := postJSON(t, base+"/v1/protect", "", map[string]any{
		"plaintext_b64": util.B64Encode([]byte("sign me")),
	})
	bundleB64, _ := enc["bundle_b64"].(string)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	sig := postJSON(t, base+"/v1/sign", "", map[string]any{
		"bundle_b64":      bundleB64,
		"private_key_pem": privPEM,
	})
	if sig["ok"] != true {
		t.Fatalf("sign failed: %v", sig)
	}
	signedBundleB64, _ := sig["bundle_b64"].(string)
	if signedBundleB64 == "" {
		t.Fatal("missing signed bundle_b64")
	}

	ver := postJSON(t, base+"/v1/verify", "", map[string]any{
		"bundle_b64":     signedBundleB64,
		"public_key_pem": pubPEM,
	})
	if ver["ok"] != true {
		t.Fatalf("verify failed: %v", ver)
	}
	if ver["valid"] != true {
		t.Fatalf("verify returned valid=false: %v", ver)
	}
}

func TestMaxRequestBytes(t *testing.T) {
	base, stop := startServer(t, serve.Options{
		AuthDisabled:    true,
		MaxRequestBytes: 1024, // very small
	})
	defer stop()
	// Build a payload larger than the cap.
	big := strings.Repeat("a", 2048)
	req, _ := http.NewRequest("POST", base+"/v1/inspect", strings.NewReader(`{"bundle_b64":"`+big+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Errorf("expected 4xx for oversize body, got %d", resp.StatusCode)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()

	// Generate some traffic.
	for i := 0; i < 3; i++ {
		postJSON(t, base+"/v1/protect", "", map[string]any{
			"plaintext_b64": util.B64Encode([]byte("x")),
		})
	}

	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{
		"vaultpack_build_info",
		"vaultpack_uptime_seconds",
		"vaultpack_http_requests_total",
		"vaultpack_http_request_duration_seconds_bucket",
		`path="/v1/protect"`,
		"vaultpack_kms_cache_entries",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q\nfull body:\n%s", want, text)
		}
	}
}

func TestKMSCache_HitsAndMisses(t *testing.T) {
	cache := serve.NewKMSCache(0, 0) // never expire, unbounded
	key := serve.CacheKey("aws", "alias/foo", []byte("wrapped-bytes"))

	if _, ok := cache.Get(key); ok {
		t.Fatal("expected miss")
	}
	cache.Put(key, []byte("plain-dek"))
	got, ok := cache.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if string(got) != "plain-dek" {
		t.Fatalf("DEK mismatch: %q", got)
	}

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Size != 1 {
		t.Errorf("unexpected stats: %+v", stats)
	}
}

func TestKMSCache_TTLExpiry(t *testing.T) {
	cache := serve.NewKMSCache(50*time.Millisecond, 0)
	key := serve.CacheKey("aws", "k1", []byte("w"))
	cache.Put(key, []byte("dek"))
	if _, ok := cache.Get(key); !ok {
		t.Fatal("expected hit before TTL")
	}
	time.Sleep(120 * time.Millisecond)
	if _, ok := cache.Get(key); ok {
		t.Fatal("expected miss after TTL")
	}
}

func TestKMSCache_FIFOEviction(t *testing.T) {
	cache := serve.NewKMSCache(0, 2)
	cache.Put(serve.CacheKey("p", "k1", []byte("w")), []byte("d1"))
	cache.Put(serve.CacheKey("p", "k2", []byte("w")), []byte("d2"))
	cache.Put(serve.CacheKey("p", "k3", []byte("w")), []byte("d3")) // evicts k1

	if _, ok := cache.Get(serve.CacheKey("p", "k1", []byte("w"))); ok {
		t.Error("expected k1 to be evicted")
	}
	if _, ok := cache.Get(serve.CacheKey("p", "k3", []byte("w"))); !ok {
		t.Error("expected k3 to still be present")
	}
	if cache.Stats().Evicted < 1 {
		t.Errorf("expected at least 1 eviction, got %d", cache.Stats().Evicted)
	}
}

// Smoke test: malformed JSON returns a structured error.
func TestMalformedJSON(t *testing.T) {
	base, stop := startServer(t, serve.Options{AuthDisabled: true})
	defer stop()
	resp, err := http.Post(base+"/v1/protect", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "invalid JSON") {
		t.Errorf("expected invalid JSON error, got %s", body)
	}
}

