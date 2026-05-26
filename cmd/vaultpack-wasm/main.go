//go:build js && wasm

// Package main builds a WebAssembly module that exposes the VaultPack SDK
// to JavaScript / TypeScript callers.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o vaultpack.wasm ./cmd/vaultpack-wasm
//
// The Go runtime's `wasm_exec.js` is required to instantiate the module.
// After `go.run(instance)`, the module installs a global object
// `globalThis.Vaultpack` with the following methods:
//
//	Vaultpack.version()                         -> string
//	Vaultpack.protect(optsObject)               -> resultObject
//	Vaultpack.decrypt(optsObject)               -> resultObject
//	Vaultpack.inspect(bundleBytes:Uint8Array)   -> resultObject
//	Vaultpack.sign(optsObject)                  -> resultObject (in-memory)
//	Vaultpack.verify(bundleBytes, optsObject)   -> resultObject
//
// Every method takes plain JS objects, never file paths — the WASM
// sandbox has no filesystem. Binary blobs are passed as Uint8Array.
package main

import (
	"encoding/base64"
	"errors"
	"syscall/js"

	"github.com/Skpow1234/Vaultpack/pkg/vaultpack"
)

func main() {
	obj := js.Global().Get("Object").New()
	obj.Set("version", js.FuncOf(jsVersion))
	obj.Set("protect", js.FuncOf(jsProtect))
	obj.Set("decrypt", js.FuncOf(jsDecrypt))
	obj.Set("inspect", js.FuncOf(jsInspect))
	obj.Set("sign", js.FuncOf(jsSign))
	obj.Set("verify", js.FuncOf(jsVerify))
	js.Global().Set("Vaultpack", obj)

	// Keep the Go runtime alive; the JS host is in control.
	select {}
}

// --- helpers ---

func jsError(msg string) any {
	return map[string]any{"ok": false, "error": msg}
}

func bytesFromJS(v js.Value) ([]byte, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}
	if v.Type() == js.TypeString {
		return base64.StdEncoding.DecodeString(v.String())
	}
	if v.InstanceOf(js.Global().Get("Uint8Array")) {
		out := make([]byte, v.Get("length").Int())
		js.CopyBytesToGo(out, v)
		return out, nil
	}
	return nil, errors.New("expected Uint8Array or base64 string")
}

func bytesToJS(b []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

func optString(opts js.Value, key string) string {
	v := opts.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return ""
	}
	return v.String()
}

func manifestToMap(m *vaultpack.Manifest) any {
	// Round-trip through JSON via internal bundle helpers for fidelity.
	data, err := vaultpack.MarshalManifest(m)
	if err != nil {
		return nil
	}
	parsed := js.Global().Get("JSON").Call("parse", string(data))
	return parsed
}

// --- exported functions ---

func jsVersion(this js.Value, args []js.Value) any {
	return vaultpack.Version
}

func jsProtect(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("protect: opts object required")
	}
	o := args[0]
	plaintext, err := bytesFromJS(o.Get("plaintext"))
	if err != nil {
		return jsError("protect: " + err.Error())
	}
	if plaintext == nil {
		return jsError("protect: plaintext (Uint8Array) is required")
	}
	key, err := bytesFromJS(o.Get("key"))
	if err != nil {
		return jsError("protect: " + err.Error())
	}
	aad, err := bytesFromJS(o.Get("aad"))
	if err != nil {
		return jsError("protect: " + err.Error())
	}
	opts := vaultpack.ProtectOptions{
		Plaintext:    plaintext,
		Key:          key,
		Password:     optString(o, "password"),
		Cipher:       optString(o, "cipher"),
		InputName:    optString(o, "inputName"),
		AAD:          aad,
		OutputWriter: discardWriter{}, // bundle bytes are captured below
	}
	// Use an in-memory buffer for the bundle (no fs in WASM).
	buf := newByteBuffer()
	opts.OutputPath = ""
	opts.OutputWriter = buf
	res, err := vaultpack.Protect(opts)
	if err != nil {
		return jsError(err.Error())
	}
	reply := map[string]any{
		"ok":       true,
		"bundle":   bytesToJS(buf.Bytes()),
		"manifest": manifestToMap(res.Manifest),
	}
	if res.GeneratedKey != nil {
		reply["generatedKey"] = bytesToJS(res.GeneratedKey)
	}
	return reply
}

func jsDecrypt(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("decrypt: opts object required")
	}
	o := args[0]
	bundleBytes, err := bytesFromJS(o.Get("bundle"))
	if err != nil {
		return jsError("decrypt: " + err.Error())
	}
	if bundleBytes == nil {
		return jsError("decrypt: bundle (Uint8Array) is required")
	}
	key, err := bytesFromJS(o.Get("key"))
	if err != nil {
		return jsError("decrypt: " + err.Error())
	}
	aad, err := bytesFromJS(o.Get("aad"))
	if err != nil {
		return jsError("decrypt: " + err.Error())
	}
	opts := vaultpack.DecryptOptions{
		InputBytes: bundleBytes,
		Key:        key,
		Password:   optString(o, "password"),
		AAD:        aad,
	}
	res, err := vaultpack.Decrypt(opts)
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":        true,
		"manifest":  manifestToMap(res.Manifest),
		"plaintext": bytesToJS(res.Plaintext),
	}
}

func jsInspect(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("inspect: bundle (Uint8Array) is required")
	}
	bundleBytes, err := bytesFromJS(args[0])
	if err != nil || bundleBytes == nil {
		return jsError("inspect: bundle (Uint8Array) is required")
	}
	// Re-use Decrypt's path-or-bytes resolver via a Decrypt-only-inspect
	// equivalent: parse the manifest only.
	tmpPath, err := writeWasmTemp(bundleBytes)
	if err != nil {
		return jsError(err.Error())
	}
	defer removeWasmTemp(tmpPath)
	m, err := vaultpack.Inspect(tmpPath)
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":       true,
		"manifest": manifestToMap(m),
	}
}

func jsSign(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("sign: opts object required")
	}
	o := args[0]
	bundleBytes, err := bytesFromJS(o.Get("bundle"))
	if err != nil || bundleBytes == nil {
		return jsError("sign: bundle (Uint8Array) is required")
	}
	pem := optString(o, "privateKeyPEM")
	if pem == "" {
		return jsError("sign: privateKeyPEM is required")
	}
	algo := optString(o, "algo")

	tmpPath, err := writeWasmTemp(bundleBytes)
	if err != nil {
		return jsError(err.Error())
	}
	defer removeWasmTemp(tmpPath)

	res, err := vaultpack.SignBundle(vaultpack.SignOptions{
		BundlePath: tmpPath,
		PrivateKey: []byte(pem),
		Algo:       algo,
	})
	if err != nil {
		return jsError(err.Error())
	}
	signed, err := readWasmTemp(tmpPath)
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":        true,
		"algorithm": res.Algorithm,
		"signedAt":  res.SignedAt,
		"signature": bytesToJS(res.Signature),
		"bundle":    bytesToJS(signed),
	}
}

func jsVerify(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("verify: opts object required")
	}
	o := args[0]
	bundleBytes, err := bytesFromJS(o.Get("bundle"))
	if err != nil || bundleBytes == nil {
		return jsError("verify: bundle (Uint8Array) is required")
	}
	pem := optString(o, "publicKeyPEM")
	if pem == "" {
		return jsError("verify: publicKeyPEM is required")
	}

	tmpPath, err := writeWasmTemp(bundleBytes)
	if err != nil {
		return jsError(err.Error())
	}
	defer removeWasmTemp(tmpPath)

	res, err := vaultpack.Verify(vaultpack.VerifyOptions{
		BundlePath: tmpPath,
		PublicKey:  []byte(pem),
	})
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":        true,
		"valid":     res.Valid,
		"algorithm": res.Algorithm,
		"signedAt":  res.SignedAt,
		"manifest":  manifestToMap(res.Manifest),
	}
}
