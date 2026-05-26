//go:build cgo && cshared

// Package main builds a C-shared library (libvaultpack.so / .dylib / .dll)
// exposing the VaultPack SDK to native callers (Python, Ruby, Java, etc).
//
// Build:
//
//	go build -buildmode=c-shared -tags cshared -o libvaultpack.so ./cmd/vaultpack-c
//
// The exported C ABI is intentionally small and JSON-based: every entry
// point takes a single null-terminated JSON string and returns a single
// malloc-allocated JSON string. The caller is responsible for releasing the
// returned string with vp_free.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/Skpow1234/Vaultpack/pkg/vaultpack"
)

// jsonReply marshals v to JSON and returns a C string that the caller must
// release with vp_free. On marshalling failure it returns a minimal error
// document.
func jsonReply(v any) *C.char {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte(`{"ok":false,"error":"jsonReply: marshal failed"}`)
	}
	return C.CString(string(data))
}

func errReply(msg string) *C.char {
	return jsonReply(map[string]any{"ok": false, "error": msg})
}

// --- vp_version ---

//export vp_version
func vp_version() *C.char {
	return C.CString(vaultpack.Version)
}

// --- vp_free ---

//export vp_free
func vp_free(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// --- vp_protect ---
//
// JSON input:
//
//	{
//	  "input_path":  "<path>",          // OR
//	  "plaintext_b64": "<base64>",
//	  "output_path": "<path>",
//	  "key_b64":   "<base64>",          // optional; 32 bytes
//	  "password":  "<utf-8>",           // optional
//	  "cipher":    "aes-256-gcm",       // optional
//	  "aad_b64":   "<base64>",          // optional
//	  "input_name":"<string>"           // optional override
//	}
//
// JSON output on success:
//
//	{"ok":true,"bundle_path":"...","generated_key_b64":"...","manifest":{...}}

//export vp_protect
func vp_protect(cOpts *C.char) *C.char {
	var in struct {
		InputPath    string `json:"input_path,omitempty"`
		PlaintextB64 string `json:"plaintext_b64,omitempty"`
		OutputPath   string `json:"output_path,omitempty"`
		KeyB64       string `json:"key_b64,omitempty"`
		Password     string `json:"password,omitempty"`
		Cipher       string `json:"cipher,omitempty"`
		AADB64       string `json:"aad_b64,omitempty"`
		InputName    string `json:"input_name,omitempty"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cOpts)), &in); err != nil {
		return errReply("invalid JSON: " + err.Error())
	}

	opts := vaultpack.ProtectOptions{
		InputPath:  in.InputPath,
		OutputPath: in.OutputPath,
		Password:   in.Password,
		Cipher:     in.Cipher,
		InputName:  in.InputName,
	}
	if in.PlaintextB64 != "" {
		pt, err := util.B64Decode(in.PlaintextB64)
		if err != nil {
			return errReply("decode plaintext_b64: " + err.Error())
		}
		opts.Plaintext = pt
	}
	if in.KeyB64 != "" {
		k, err := util.B64Decode(in.KeyB64)
		if err != nil {
			return errReply("decode key_b64: " + err.Error())
		}
		opts.Key = k
	}
	if in.AADB64 != "" {
		a, err := util.B64Decode(in.AADB64)
		if err != nil {
			return errReply("decode aad_b64: " + err.Error())
		}
		opts.AAD = a
	}

	res, err := vaultpack.Protect(opts)
	if err != nil {
		return errReply(err.Error())
	}
	out := map[string]any{
		"ok":          true,
		"bundle_path": res.BundlePath,
		"manifest":    res.Manifest,
	}
	if res.GeneratedKey != nil {
		out["generated_key_b64"] = util.B64Encode(res.GeneratedKey)
	}
	return jsonReply(out)
}

// --- vp_decrypt ---
//
// JSON input:
//
//	{
//	  "input_path":  "<path>",          // OR
//	  "bundle_b64":  "<base64>",
//	  "output_path": "<path>",          // OR omit to return plaintext_b64
//	  "key_b64":   "<base64>",          // OR
//	  "password":  "<utf-8>",
//	  "aad_b64":   "<base64>"           // optional
//	}
//
// JSON output:
//
//	{"ok":true,"manifest":{...},"plaintext_b64":"..."}

//export vp_decrypt
func vp_decrypt(cOpts *C.char) *C.char {
	var in struct {
		InputPath  string `json:"input_path,omitempty"`
		BundleB64  string `json:"bundle_b64,omitempty"`
		OutputPath string `json:"output_path,omitempty"`
		KeyB64     string `json:"key_b64,omitempty"`
		Password   string `json:"password,omitempty"`
		AADB64     string `json:"aad_b64,omitempty"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cOpts)), &in); err != nil {
		return errReply("invalid JSON: " + err.Error())
	}

	opts := vaultpack.DecryptOptions{
		InputPath:  in.InputPath,
		OutputPath: in.OutputPath,
		Password:   in.Password,
	}
	if in.BundleB64 != "" {
		b, err := util.B64Decode(in.BundleB64)
		if err != nil {
			return errReply("decode bundle_b64: " + err.Error())
		}
		opts.InputBytes = b
	}
	if in.KeyB64 != "" {
		k, err := util.B64Decode(in.KeyB64)
		if err != nil {
			return errReply("decode key_b64: " + err.Error())
		}
		opts.Key = k
	}
	if in.AADB64 != "" {
		a, err := util.B64Decode(in.AADB64)
		if err != nil {
			return errReply("decode aad_b64: " + err.Error())
		}
		opts.AAD = a
	}

	res, err := vaultpack.Decrypt(opts)
	if err != nil {
		return errReply(err.Error())
	}
	out := map[string]any{
		"ok":       true,
		"manifest": res.Manifest,
	}
	if res.Plaintext != nil {
		out["plaintext_b64"] = util.B64Encode(res.Plaintext)
	}
	return jsonReply(out)
}

// --- vp_inspect ---
//
// JSON input: a raw path string (NOT a JSON object). Returns
// {"ok":true,"manifest":{...}}.

//export vp_inspect
func vp_inspect(cPath *C.char) *C.char {
	path := C.GoString(cPath)
	m, err := vaultpack.Inspect(path)
	if err != nil {
		return errReply(err.Error())
	}
	return jsonReply(map[string]any{"ok": true, "manifest": m})
}

// --- vp_sign ---
//
// JSON input:
//
//	{
//	  "bundle_path":      "<path>",
//	  "private_key_pem":  "<pem>",      // OR
//	  "private_key_path": "<path>",
//	  "algo":             "ed25519"     // optional
//	}

//export vp_sign
func vp_sign(cOpts *C.char) *C.char {
	var in struct {
		BundlePath     string `json:"bundle_path"`
		PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
		PrivateKeyPath string `json:"private_key_path,omitempty"`
		Algo           string `json:"algo,omitempty"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cOpts)), &in); err != nil {
		return errReply("invalid JSON: " + err.Error())
	}
	opts := vaultpack.SignOptions{
		BundlePath:     in.BundlePath,
		PrivateKeyPath: in.PrivateKeyPath,
		Algo:           in.Algo,
	}
	if in.PrivateKeyPEM != "" {
		opts.PrivateKey = []byte(in.PrivateKeyPEM)
	}
	res, err := vaultpack.SignBundle(opts)
	if err != nil {
		return errReply(err.Error())
	}
	return jsonReply(map[string]any{
		"ok":            true,
		"algorithm":     res.Algorithm,
		"signed_at":     res.SignedAt,
		"signature_b64": util.B64Encode(res.Signature),
	})
}

// --- vp_verify ---
//
// JSON input:
//
//	{
//	  "bundle_path":     "<path>",
//	  "public_key_pem":  "<pem>",       // OR
//	  "public_key_path": "<path>"
//	}

//export vp_verify
func vp_verify(cOpts *C.char) *C.char {
	var in struct {
		BundlePath    string `json:"bundle_path"`
		PublicKeyPEM  string `json:"public_key_pem,omitempty"`
		PublicKeyPath string `json:"public_key_path,omitempty"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cOpts)), &in); err != nil {
		return errReply("invalid JSON: " + err.Error())
	}
	opts := vaultpack.VerifyOptions{
		BundlePath:    in.BundlePath,
		PublicKeyPath: in.PublicKeyPath,
	}
	if in.PublicKeyPEM != "" {
		opts.PublicKey = []byte(in.PublicKeyPEM)
	}
	res, err := vaultpack.Verify(opts)
	if err != nil {
		return errReply(err.Error())
	}
	return jsonReply(map[string]any{
		"ok":        true,
		"valid":     res.Valid,
		"algorithm": res.Algorithm,
		"signed_at": res.SignedAt,
		"manifest":  res.Manifest,
	})
}

func main() {}
