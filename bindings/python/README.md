# vaultpack — Python bindings

`pip install vaultpack` provides a small `ctypes` wrapper around
`libvaultpack`, the VaultPack C-shared library. No C compiler is required
at install time, but the native library must be present on the host.

## Installation

```bash
pip install vaultpack
```

Then make `libvaultpack.{so,dylib,dll}` discoverable by one of:

- Setting `$VAULTPACK_LIB=/abs/path/to/libvaultpack.so`.
- Dropping it next to the installed `vaultpack/` package directory.
- Putting it on `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / `PATH` so the
  system loader finds it.

Build the library from the VaultPack source tree:

```bash
go build -buildmode=c-shared -tags cshared \
  -o libvaultpack.so ./cmd/vaultpack-c
```

(See `cmd/vaultpack-c/README.md` for per-OS instructions.)

## Quick start

```python
import base64
import vaultpack

# Encrypt with a generated key.
res = vaultpack.protect(
    input_path="secret.txt",
    output_path="secret.vpack",
)
key_b64 = res["generated_key_b64"]   # store this somewhere safe!
print("manifest:", res["manifest"])

# Decrypt back.
out = vaultpack.decrypt(
    input_path="secret.vpack",
    key_b64=key_b64,
    output_path="secret.out",
)
print("decrypted manifest:", out["manifest"])

# Or do it entirely in memory:
key = base64.b64decode(key_b64)
res2 = vaultpack.decrypt(
    input_path="secret.vpack",
    key=key,
)
plaintext = base64.b64decode(res2["plaintext_b64"])
print(plaintext)
```

## API

| Function                          | Purpose                              |
|-----------------------------------|--------------------------------------|
| `version() -> str`                | libvaultpack semver                  |
| `protect(...) -> dict`            | Encrypt → .vpack bundle              |
| `decrypt(...) -> dict`            | Decrypt a .vpack bundle              |
| `inspect(path) -> dict`           | Read the manifest only               |
| `sign(...) -> dict`               | Add/replace detached signature       |
| `verify(...) -> dict`             | Verify detached signature            |

Every call returns a `dict` (JSON-deserialized). On error a
`vaultpack.VaultpackError` is raised with the underlying message.

## Supported modes (v0.1)

- Symmetric key file (auto-generated or supplied).
- Password-based (argon2id / scrypt / pbkdf2-sha256).
- Detached signatures (ed25519 / ecdsa-p256/p384 / rsa-pss / ml-dsa / slh-dsa).

Hybrid (recipient-based) encryption, KMS wrapping, key splitting,
compression, and transparency-log uploads currently require the
`vaultpack` CLI; they will be added in a future minor release.

## License

MIT.
