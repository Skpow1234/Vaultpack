package serve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/Skpow1234/Vaultpack/pkg/vaultpack"
)

// registerRoutes wires the HTTP endpoints. The contract is the same as
// the C-shared library and WASM bindings: JSON in, JSON out, with an
// {"ok": true|false, ...} envelope.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.metrics.AttachKMSCache(s.kms)
	s.mux.Handle("/metrics", s.metrics)

	s.mux.HandleFunc("/v1/version", s.handleVersion)
	s.mux.HandleFunc("/v1/protect", s.handleProtect)
	s.mux.HandleFunc("/v1/decrypt", s.handleDecrypt)
	s.mux.HandleFunc("/v1/inspect", s.handleInspect)
	s.mux.HandleFunc("/v1/sign", s.handleSign)
	s.mux.HandleFunc("/v1/verify", s.handleVerify)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"sdk_version": vaultpack.Version,
		"api_version": "v1",
	})
}

// --- /v1/protect ---

type protectRequest struct {
	PlaintextB64 string `json:"plaintext_b64,omitempty"`
	InputPath    string `json:"input_path,omitempty"`
	OutputPath   string `json:"output_path,omitempty"`
	KeyB64       string `json:"key_b64,omitempty"`
	Password     string `json:"password,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	AADB64       string `json:"aad_b64,omitempty"`
	InputName    string `json:"input_name,omitempty"`

	// ReturnBundle, if true, includes the bundle bytes (base64) in the
	// reply. Defaults to true when OutputPath is empty.
	ReturnBundle *bool `json:"return_bundle,omitempty"`
}

func (s *Server) handleProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req protectRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	opts := vaultpack.ProtectOptions{
		InputPath:  req.InputPath,
		OutputPath: req.OutputPath,
		Password:   req.Password,
		Cipher:     req.Cipher,
		InputName:  req.InputName,
	}
	if req.PlaintextB64 != "" {
		pt, err := util.B64Decode(req.PlaintextB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode plaintext_b64: "+err.Error())
			return
		}
		opts.Plaintext = pt
	}
	if req.KeyB64 != "" {
		k, err := util.B64Decode(req.KeyB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode key_b64: "+err.Error())
			return
		}
		opts.Key = k
	}
	if req.AADB64 != "" {
		a, err := util.B64Decode(req.AADB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode aad_b64: "+err.Error())
			return
		}
		opts.AAD = a
	}

	// Decide whether to return the bundle bytes. Default behavior:
	// return bytes only when no OutputPath was supplied.
	returnBundle := req.ReturnBundle != nil && *req.ReturnBundle
	if req.ReturnBundle == nil && req.OutputPath == "" {
		returnBundle = true
	}
	var bundleSink *limitedBuffer
	if returnBundle {
		bundleSink = newLimitedBuffer(s.opts.MaxRequestBytes)
		opts.OutputWriter = bundleSink
		opts.OutputPath = ""
	}

	res, err := vaultpack.Protect(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	out := map[string]any{
		"ok":          true,
		"bundle_path": res.BundlePath,
		"manifest":    res.Manifest,
	}
	if res.GeneratedKey != nil {
		out["generated_key_b64"] = util.B64Encode(res.GeneratedKey)
	}
	if bundleSink != nil {
		out["bundle_b64"] = util.B64Encode(bundleSink.Bytes())
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /v1/decrypt ---

type decryptRequest struct {
	InputPath  string `json:"input_path,omitempty"`
	BundleB64  string `json:"bundle_b64,omitempty"`
	OutputPath string `json:"output_path,omitempty"`
	KeyB64     string `json:"key_b64,omitempty"`
	Password   string `json:"password,omitempty"`
	AADB64     string `json:"aad_b64,omitempty"`

	// ReturnPlaintext defaults to true when OutputPath is empty.
	ReturnPlaintext *bool `json:"return_plaintext,omitempty"`
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req decryptRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	opts := vaultpack.DecryptOptions{
		InputPath:  req.InputPath,
		OutputPath: req.OutputPath,
		Password:   req.Password,
	}
	if req.BundleB64 != "" {
		b, err := util.B64Decode(req.BundleB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode bundle_b64: "+err.Error())
			return
		}
		opts.InputBytes = b
	}
	if req.KeyB64 != "" {
		k, err := util.B64Decode(req.KeyB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode key_b64: "+err.Error())
			return
		}
		opts.Key = k
	}
	if req.AADB64 != "" {
		a, err := util.B64Decode(req.AADB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode aad_b64: "+err.Error())
			return
		}
		opts.AAD = a
	}

	res, err := vaultpack.Decrypt(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	out := map[string]any{
		"ok":       true,
		"manifest": res.Manifest,
	}
	wantPT := req.ReturnPlaintext != nil && *req.ReturnPlaintext
	if req.ReturnPlaintext == nil && req.OutputPath == "" {
		wantPT = true
	}
	if wantPT && res.Plaintext != nil {
		out["plaintext_b64"] = util.B64Encode(res.Plaintext)
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /v1/inspect ---

type inspectRequest struct {
	InputPath string `json:"input_path,omitempty"`
	BundleB64 string `json:"bundle_b64,omitempty"`
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req inspectRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.InputPath != "" {
		m, err := vaultpack.Inspect(req.InputPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
		return
	}
	if req.BundleB64 != "" {
		b, err := util.B64Decode(req.BundleB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode bundle_b64: "+err.Error())
			return
		}
		m, err := vaultpack.InspectBytes(b)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
		return
	}
	writeError(w, http.StatusBadRequest, "one of input_path or bundle_b64 is required")
}

// --- /v1/sign ---

type signRequest struct {
	BundlePath     string `json:"bundle_path,omitempty"`
	BundleB64      string `json:"bundle_b64,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	Algo           string `json:"algo,omitempty"`
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req signRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	signOpts := vaultpack.SignOptions{
		BundlePath:     req.BundlePath,
		PrivateKeyPath: req.PrivateKeyPath,
		Algo:           req.Algo,
	}
	if req.PrivateKeyPEM != "" {
		signOpts.PrivateKey = []byte(req.PrivateKeyPEM)
	}

	if req.BundleB64 != "" {
		bundleBytes, err := util.B64Decode(req.BundleB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode bundle_b64: "+err.Error())
			return
		}
		signed, sres, err := vaultpack.SignBytes(bundleBytes, signOpts)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"algorithm":     sres.Algorithm,
			"signed_at":     sres.SignedAt,
			"signature_b64": util.B64Encode(sres.Signature),
			"bundle_b64":    util.B64Encode(signed),
		})
		return
	}
	if req.BundlePath == "" {
		writeError(w, http.StatusBadRequest, "one of bundle_path or bundle_b64 is required")
		return
	}
	sres, err := vaultpack.SignBundle(signOpts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"algorithm":     sres.Algorithm,
		"signed_at":     sres.SignedAt,
		"signature_b64": util.B64Encode(sres.Signature),
	})
}

// --- /v1/verify ---

type verifyRequest struct {
	BundlePath    string `json:"bundle_path,omitempty"`
	BundleB64     string `json:"bundle_b64,omitempty"`
	PublicKeyPEM  string `json:"public_key_pem,omitempty"`
	PublicKeyPath string `json:"public_key_path,omitempty"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req verifyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	verifyOpts := vaultpack.VerifyOptions{
		BundlePath:    req.BundlePath,
		PublicKeyPath: req.PublicKeyPath,
	}
	if req.PublicKeyPEM != "" {
		verifyOpts.PublicKey = []byte(req.PublicKeyPEM)
	}
	var (
		vres *vaultpack.VerifyResult
		err  error
	)
	if req.BundleB64 != "" {
		bundleBytes, derr := util.B64Decode(req.BundleB64)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "decode bundle_b64: "+derr.Error())
			return
		}
		vres, err = vaultpack.VerifyBytes(bundleBytes, verifyOpts)
	} else if req.BundlePath != "" {
		vres, err = vaultpack.Verify(verifyOpts)
	} else {
		writeError(w, http.StatusBadRequest, "one of bundle_path or bundle_b64 is required")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"valid":     vres.Valid,
		"algorithm": vres.Algorithm,
		"signed_at": vres.SignedAt,
		"manifest":  vres.Manifest,
	})
}

// --- helpers ---

func readJSON(r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !startsWithCT(ct, "application/json") {
		return fmt.Errorf("Content-Type must be application/json, got %q", ct)
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func startsWithCT(ct, want string) bool {
	if len(ct) < len(want) {
		return false
	}
	return ct[:len(want)] == want
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}

// limitedBuffer caps in-memory writes so an attacker can't OOM the
// server by asking us to encrypt a huge plaintext and return the bundle.
type limitedBuffer struct {
	max  int64
	used int64
	buf  []byte
}

func newLimitedBuffer(max int64) *limitedBuffer { return &limitedBuffer{max: max} }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.used+int64(len(p)) > b.max {
		return 0, io.ErrShortBuffer
	}
	b.buf = append(b.buf, p...)
	b.used += int64(len(p))
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buf }
