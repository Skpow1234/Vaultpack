package serve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/audit"
	"github.com/Skpow1234/Vaultpack/internal/bundle"
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
	s.mux.HandleFunc("/v1/rewrap", s.handleRewrap)
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

type recipientJSON struct {
	PublicKeyPEM  string `json:"public_key_pem,omitempty"`
	PublicKeyPath string `json:"public_key_path,omitempty"`
}

type protectRequest struct {
	PlaintextB64 string `json:"plaintext_b64,omitempty"`
	InputPath    string `json:"input_path,omitempty"`
	OutputPath   string `json:"output_path,omitempty"`
	KeyB64       string `json:"key_b64,omitempty"`
	Password     string `json:"password,omitempty"`
	KDFAlgo      string `json:"kdf_algo,omitempty"`
	KMSProvider  string `json:"kms_provider,omitempty"`
	KMSKeyID     string `json:"kms_key_id,omitempty"`
	Recipients   []recipientJSON `json:"recipients,omitempty"`
	Compress     string `json:"compress,omitempty"`
	SplitShares    int `json:"split_shares,omitempty"`
	SplitThreshold int `json:"split_threshold,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	ChunkSize    int    `json:"chunk_size,omitempty"`
	HashAlgo     string `json:"hash_algo,omitempty"`
	AADB64       string `json:"aad_b64,omitempty"`
	InputName    string `json:"input_name,omitempty"`
	ParallelWorkers int `json:"parallel_workers,omitempty"`

	SignPrivateKeyPEM  string `json:"sign_private_key_pem,omitempty"`
	SignPrivateKeyPath string `json:"sign_private_key_path,omitempty"`
	SignAlgo           string `json:"sign_algo,omitempty"`

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

	inputRef := req.InputPath
	if inputRef == "" {
		inputRef = req.InputName
	}
	if err := s.enforcePolicy(audit.OpProtect, inputRef, nil); err != nil {
		writePolicyError(w, err)
		return
	}

	opts, err := req.toProtectOptions(s.opts.MaxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

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
		s.auditEntry(audit.OpProtect, inputRef, req.OutputPath, "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpProtect, inputRef, res.BundlePath, "", true, "")

	out := map[string]any{
		"ok":          true,
		"bundle_path": res.BundlePath,
		"manifest":    res.Manifest,
	}
	if res.GeneratedKey != nil {
		out["generated_key_b64"] = util.B64Encode(res.GeneratedKey)
	}
	if len(res.Shares) > 0 {
		shares := make([]map[string]any, len(res.Shares))
		for i, sh := range res.Shares {
			shares[i] = map[string]any{
				"index":    sh.Index,
				"data_b64": util.B64Encode(sh.Data),
			}
		}
		out["shares"] = shares
	}
	if res.SignatureAlgo != "" {
		out["signature_algo"] = res.SignatureAlgo
		out["signature_b64"] = util.B64Encode(res.Signature)
	}
	if bundleSink != nil {
		out["bundle_b64"] = util.B64Encode(bundleSink.Bytes())
	}
	writeJSON(w, http.StatusOK, out)
}

type decryptRequest struct {
	InputPath  string `json:"input_path,omitempty"`
	BundleB64  string `json:"bundle_b64,omitempty"`
	OutputPath string `json:"output_path,omitempty"`
	KeyB64     string `json:"key_b64,omitempty"`
	Password   string `json:"password,omitempty"`
	KMSProvider string `json:"kms_provider,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	AADB64     string `json:"aad_b64,omitempty"`
	ParallelWorkers int `json:"parallel_workers,omitempty"`
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

	bundleRef, manifest, err := loadManifest(req.InputPath, req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.enforcePolicy(audit.OpDecrypt, bundleRef, manifest); err != nil {
		writePolicyError(w, err)
		return
	}

	opts := vaultpack.DecryptOptions{
		InputPath:       req.InputPath,
		OutputPath:      req.OutputPath,
		Password:        req.Password,
		KMSProvider:     req.KMSProvider,
		PrivateKeyPath:  req.PrivateKeyPath,
		ParallelWorkers: req.ParallelWorkers,
		KMSUnwrap: func(wrapped []byte, keyID string) ([]byte, error) {
			return s.unwrapKMS(req.KMSProvider, wrapped, keyID)
		},
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
	if req.PrivateKeyPEM != "" {
		opts.PrivateKey = []byte(req.PrivateKeyPEM)
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
		s.auditEntry(audit.OpDecrypt, bundleRef, req.OutputPath, "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpDecrypt, bundleRef, req.OutputPath, "", true, "")

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

	bundleRef, manifest, err := loadManifest(req.InputPath, req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.enforcePolicy(audit.OpInspect, bundleRef, manifest); err != nil {
		writePolicyError(w, err)
		return
	}

	if req.InputPath != "" {
		m, err := vaultpack.Inspect(req.InputPath)
		if err != nil {
			s.auditEntry(audit.OpInspect, bundleRef, "", "", false, err.Error())
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.auditEntry(audit.OpInspect, bundleRef, "", "", true, "")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
		return
	}
	b, err := util.B64Decode(req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decode bundle_b64: "+err.Error())
		return
	}
	m, err := vaultpack.InspectBytes(b)
	if err != nil {
		s.auditEntry(audit.OpInspect, bundleRef, "", "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpInspect, bundleRef, "", "", true, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
}

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

	bundleRef, manifest, err := loadManifest(req.BundlePath, req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.enforcePolicy(audit.OpSign, bundleRef, manifest); err != nil {
		writePolicyError(w, err)
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
			s.auditEntry(audit.OpSign, bundleRef, "", "", false, err.Error())
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.auditEntry(audit.OpSign, bundleRef, "", "", true, "")
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
		s.auditEntry(audit.OpSign, bundleRef, "", "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpSign, bundleRef, "", "", true, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"algorithm":     sres.Algorithm,
		"signed_at":     sres.SignedAt,
		"signature_b64": util.B64Encode(sres.Signature),
	})
}

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

	bundleRef, manifest, err := loadManifest(req.BundlePath, req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.enforcePolicy(audit.OpVerify, bundleRef, manifest); err != nil {
		writePolicyError(w, err)
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
		s.auditEntry(audit.OpVerify, bundleRef, "", "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpVerify, bundleRef, "", "", true, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"valid":     vres.Valid,
		"algorithm": vres.Algorithm,
		"signed_at": vres.SignedAt,
		"manifest":  vres.Manifest,
	})
}

type rewrapRequest struct {
	InputPath   string `json:"input_path,omitempty"`
	BundleB64   string `json:"bundle_b64,omitempty"`
	OutputPath  string `json:"output_path,omitempty"`
	KMSProvider string `json:"kms_provider,omitempty"`
	FromKeyID   string `json:"from_key_id,omitempty"`
	ToKeyID     string `json:"to_key_id,omitempty"`
	ReturnBundle *bool `json:"return_bundle,omitempty"`
}

func (s *Server) handleRewrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req rewrapRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	bundleRef, manifest, err := loadManifest(req.InputPath, req.BundleB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.enforcePolicy(audit.OpRewrap, bundleRef, manifest); err != nil {
		writePolicyError(w, err)
		return
	}

	opts := vaultpack.RewrapOptions{
		InputPath:   req.InputPath,
		OutputPath:  req.OutputPath,
		KMSProvider: req.KMSProvider,
		FromKeyID:   req.FromKeyID,
		ToKeyID:     req.ToKeyID,
	}
	if req.BundleB64 != "" {
		b, err := util.B64Decode(req.BundleB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "decode bundle_b64: "+err.Error())
			return
		}
		opts.InputBytes = b
	}

	res, err := vaultpack.Rewrap(opts)
	if err != nil {
		s.auditEntry(audit.OpRewrap, bundleRef, req.OutputPath, "", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditEntry(audit.OpRewrap, bundleRef, res.OutputPath, "", true, "")

	out := map[string]any{
		"ok":          true,
		"manifest":    res.Manifest,
		"bundle_path": res.OutputPath,
	}
	returnBundle := req.ReturnBundle != nil && *req.ReturnBundle
	if returnBundle && res.OutputPath != "" {
		if b, err := os.ReadFile(res.OutputPath); err == nil {
			out["bundle_b64"] = util.B64Encode(b)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (req *protectRequest) toProtectOptions(maxBytes int64) (vaultpack.ProtectOptions, error) {
	opts := vaultpack.ProtectOptions{
		InputPath:       req.InputPath,
		OutputPath:      req.OutputPath,
		Password:        req.Password,
		KDFAlgo:         req.KDFAlgo,
		KMSProvider:     req.KMSProvider,
		KMSKeyID:        req.KMSKeyID,
		Compress:        req.Compress,
		SplitShares:     req.SplitShares,
		SplitThreshold:  req.SplitThreshold,
		Cipher:          req.Cipher,
		ChunkSize:       req.ChunkSize,
		HashAlgo:        req.HashAlgo,
		InputName:       req.InputName,
		ParallelWorkers: req.ParallelWorkers,
	}
	if req.PlaintextB64 != "" {
		pt, err := util.B64Decode(req.PlaintextB64)
		if err != nil {
			return opts, fmt.Errorf("decode plaintext_b64: %w", err)
		}
		opts.Plaintext = pt
	}
	if req.KeyB64 != "" {
		k, err := util.B64Decode(req.KeyB64)
		if err != nil {
			return opts, fmt.Errorf("decode key_b64: %w", err)
		}
		opts.Key = k
	}
	if req.AADB64 != "" {
		a, err := util.B64Decode(req.AADB64)
		if err != nil {
			return opts, fmt.Errorf("decode aad_b64: %w", err)
		}
		opts.AAD = a
	}
	if len(req.Recipients) > 0 {
		recipients := make([]vaultpack.Recipient, len(req.Recipients))
		for i, r := range req.Recipients {
			if r.PublicKeyPEM != "" {
				recipients[i].PublicKeyPEM = []byte(r.PublicKeyPEM)
			}
			recipients[i].PublicKeyPath = r.PublicKeyPath
		}
		opts.Recipients = recipients
	}
	if req.SignPrivateKeyPEM != "" || req.SignPrivateKeyPath != "" {
		opts.Sign = &vaultpack.SignParams{
			PrivateKey:     []byte(req.SignPrivateKeyPEM),
			PrivateKeyPath: req.SignPrivateKeyPath,
			Algo:           req.SignAlgo,
		}
	}
	_ = maxBytes
	return opts, nil
}

func loadManifest(path, b64 string) (string, *bundle.Manifest, error) {
	switch {
	case path != "" && b64 != "":
		return "", nil, fmt.Errorf("only one of input_path/bundle_path or bundle_b64 may be set")
	case path != "":
		br, err := bundle.Read(path)
		if err != nil {
			return "", nil, err
		}
		return path, br.Manifest, nil
	case b64 != "":
		data, err := util.B64Decode(b64)
		if err != nil {
			return "", nil, fmt.Errorf("decode bundle_b64: %w", err)
		}
		br, err := bundle.ReadBytes(data)
		if err != nil {
			return "", nil, err
		}
		return "<memory>", br.Manifest, nil
	default:
		return "", nil, fmt.Errorf("one of input_path/bundle_path or bundle_b64 is required")
	}
}


func writePolicyError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusForbidden, err.Error())
}

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
