# @vaultpack/wasm

WebAssembly bindings for [VaultPack](https://github.com/Skpow1234/Vaultpack)
— encrypt, decrypt, sign, and verify `.vpack` bundles directly in the
browser or in Node.js, with no native code required at install time.

## Installation

```bash
npm install @vaultpack/wasm
```

Two files ship with the package:

- `vaultpack.wasm`         — the Go-compiled WASM module (~8 MB).
- `vaultpack-loader.js`    — a tiny ESM loader that pulls in Go's
  `wasm_exec.js` and instantiates the module.

Build from the VaultPack source tree with:

```bash
GOOS=js GOARCH=wasm go build -o vaultpack.wasm ./cmd/vaultpack-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .
```

## Quick start (Node 20+)

```javascript
import { loadVaultpack } from "@vaultpack/wasm";

const Vaultpack = await loadVaultpack(
  new URL("./vaultpack.wasm", import.meta.url)
);

console.log("Version:", Vaultpack.version());

// Encrypt with a generated key.
const plaintext = new TextEncoder().encode("hello, sdk");
const enc = Vaultpack.protect({ plaintext });
if (!enc.ok) throw new Error(enc.error);
console.log("manifest:", enc.manifest);

// Decrypt.
const dec = Vaultpack.decrypt({
  bundle: enc.bundle,
  key: enc.generatedKey,
});
if (!dec.ok) throw new Error(dec.error);
console.log(new TextDecoder().decode(dec.plaintext));
```

## Quick start (browser)

```html
<script type="module">
  import { loadVaultpack } from "./vaultpack-loader.js";
  const Vaultpack = await loadVaultpack("./vaultpack.wasm");
  document.body.textContent = "VaultPack " + Vaultpack.version();
</script>
```

## API

See `vaultpack.d.ts` for the full TypeScript surface. The shape is the
same as the C-shared and Python wrappers:

- `version() -> string`
- `protect({plaintext, key?, password?, cipher?, inputName?, aad?})`
- `decrypt({bundle, key?, password?, aad?})`
- `inspect(bundleBytes)`
- `sign({bundle, privateKeyPEM, algo?})`
- `verify({bundle, publicKeyPEM})`

Every call returns either `{ok: true, ...}` on success or
`{ok: false, error: "..."}` on failure.

## Supported modes (v0.1)

- Symmetric key (auto-generated or supplied).
- Password-based (argon2id / scrypt / pbkdf2-sha256).
- Detached signatures (ed25519 / ecdsa / rsa-pss / ml-dsa / slh-dsa).
- Bundle inspection.

Hybrid (recipient-based) encryption, KMS wrapping, key splitting,
compression, and Sigstore transparency uploads currently require the
`vaultpack` CLI; they will be added in a future minor release.

## License

MIT.
