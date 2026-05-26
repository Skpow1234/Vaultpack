// End-to-end smoke test for the VaultPack WASM bindings.
// Usage: node bindings/typescript/test/smoke.mjs

import { loadVaultpack } from "../vaultpack-loader.js";

function assert(cond, msg) {
  if (!cond) throw new Error("ASSERT FAILED: " + msg);
}

function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const wasmURL = new URL("../vaultpack.wasm", import.meta.url);
const wasmExecURL = new URL("../wasm_exec.js", import.meta.url);

const Vaultpack = await loadVaultpack(wasmURL, { wasmExecURL });

// 1. version
const v = Vaultpack.version();
assert(typeof v === "string" && v.split(".").length === 3, `version=${v}`);
console.log("version:", v);

// 2. protect + decrypt round-trip (generated key)
const plaintext = new TextEncoder().encode("the quick brown fox jumps over the lazy dog");
const enc = Vaultpack.protect({ plaintext, inputName: "fox.txt" });
assert(enc.ok, "protect: " + (enc.error || ""));
assert(enc.bundle instanceof Uint8Array && enc.bundle.length > 0, "bundle bytes");
assert(enc.generatedKey instanceof Uint8Array && enc.generatedKey.length === 32, "32-byte generated key");
console.log("protect ok, bundle:", enc.bundle.length, "bytes");

const dec = Vaultpack.decrypt({ bundle: enc.bundle, key: enc.generatedKey });
assert(dec.ok, "decrypt: " + (dec.error || ""));
assert(eqBytes(dec.plaintext, plaintext), "plaintext mismatch");
console.log("decrypt ok");

// 3. password round-trip
const enc2 = Vaultpack.protect({
  plaintext,
  password: "correct horse battery staple",
  cipher: "chacha20-poly1305",
});
assert(enc2.ok, "protect pw: " + (enc2.error || ""));
const dec2 = Vaultpack.decrypt({ bundle: enc2.bundle, password: "correct horse battery staple" });
assert(dec2.ok, "decrypt pw: " + (dec2.error || ""));
assert(eqBytes(dec2.plaintext, plaintext), "plaintext mismatch (pw)");
console.log("password round-trip ok");

// 4. wrong password fails
const bad = Vaultpack.decrypt({ bundle: enc2.bundle, password: "wrong" });
assert(bad.ok === false, "wrong password should fail");
console.log("wrong-password rejected:", bad.error);

// 5. inspect
const ins = Vaultpack.inspect(enc.bundle);
assert(ins.ok, "inspect: " + (ins.error || ""));
assert(ins.manifest.input.name === "fox.txt", "name preserved");
console.log("inspect ok, AEAD:", ins.manifest.encryption.aead);

console.log("\nALL WASM SMOKE TESTS PASSED");
process.exit(0);
