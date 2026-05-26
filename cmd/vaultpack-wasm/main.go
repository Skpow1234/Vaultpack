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
//	Vaultpack.verify(optsObject)                -> resultObject
//
// Every method takes plain JS objects, never file paths — the WASM
// sandbox has no filesystem. Binary blobs are passed as Uint8Array.
package main

import (
	"bytes"
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
	select {}
}

func jsError(msg string) any { return map[string]any{"ok": false, "error": msg} }

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

func manifestJS(m *vaultpack.Manifest) any {
	data, err := vaultpack.MarshalManifest(m)
	if err != nil {
		return nil
	}
	return js.Global().Get("JSON").Call("parse", string(data))
}

func jsVersion(this js.Value, args []js.Value) any { return vaultpack.Version }

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
	var buf bytes.Buffer
	res, err := vaultpack.Protect(vaultpack.ProtectOptions{
		Plaintext:    plaintext,
		Key:          key,
		Password:     optString(o, "password"),
		Cipher:       optString(o, "cipher"),
		InputName:    optString(o, "inputName"),
		AAD:          aad,
		OutputWriter: &buf,
	})
	if err != nil {
		return jsError(err.Error())
	}
	reply := map[string]any{
		"ok":       true,
		"bundle":   bytesToJS(buf.Bytes()),
		"manifest": manifestJS(res.Manifest),
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
	if err != nil || bundleBytes == nil {
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
	res, err := vaultpack.Decrypt(vaultpack.DecryptOptions{
		InputBytes: bundleBytes,
		Key:        key,
		Password:   optString(o, "password"),
		AAD:        aad,
	})
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":        true,
		"manifest":  manifestJS(res.Manifest),
		"plaintext": bytesToJS(res.Plaintext),
	}
}

func jsInspect(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("inspect: bundle (Uint8Array) is required")
	}
	b, err := bytesFromJS(args[0])
	if err != nil || b == nil {
		return jsError("inspect: bundle (Uint8Array) is required")
	}
	m, err := vaultpack.InspectBytes(b)
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{"ok": true, "manifest": manifestJS(m)}
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
	signed, res, err := vaultpack.SignBytes(bundleBytes, vaultpack.SignOptions{
		PrivateKey: []byte(pem),
		Algo:       optString(o, "algo"),
	})
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
	res, err := vaultpack.VerifyBytes(bundleBytes, vaultpack.VerifyOptions{
		PublicKey: []byte(pem),
	})
	if err != nil {
		return jsError(err.Error())
	}
	return map[string]any{
		"ok":        true,
		"valid":     res.Valid,
		"algorithm": res.Algorithm,
		"signedAt":  res.SignedAt,
		"manifest":  manifestJS(res.Manifest),
	}
}
