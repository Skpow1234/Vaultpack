# VaultPack

A cross-platform CLI that encrypts, hashes, and signs data artifacts into portable `.vpack` bundles.

One tool. One bundle. Encryption + integrity + authenticity.

## Quick Start

```bash
# Encrypt a file (generates a key automatically, default cipher: AES-256-GCM)
vaultpack protect --in config.json

# Encrypt with ChaCha20-Poly1305 or XChaCha20-Poly1305
vaultpack protect --in config.json --cipher chacha20-poly1305
vaultpack protect --in config.json --cipher xchacha20-poly1305

# Encrypt with a password instead of a key file
vaultpack protect --in config.json --password "my-secret-passphrase"
vaultpack protect --in config.json --password "pass" --kdf scrypt
vaultpack protect --in config.json --password-file pw.txt --kdf pbkdf2-sha256

# Decrypt (cipher is auto-detected from the bundle)
vaultpack decrypt --in config.json.vpack --out config.json --key config.json.key

# Decrypt a password-protected bundle
vaultpack decrypt --in config.json.vpack --out config.json --password "my-secret-passphrase"

# Encrypt for a recipient's public key (hybrid encryption)
vaultpack keygen --out alice --algo x25519-aes-256-gcm
vaultpack protect --in config.json --recipient alice.pub
vaultpack decrypt --in config.json.vpack --out config.json --privkey alice.key

# Inspect the bundle metadata
vaultpack inspect --in config.json.vpack

# Hash a file (default: SHA-256; also supports sha512, sha3-256, sha3-512, blake2b-256, blake2b-512, blake3)
vaultpack hash --in export.csv
vaultpack hash --in export.csv --algo blake3

# Generate a signing key pair (default: Ed25519)
vaultpack keygen --out signing

# Generate ECDSA or RSA-PSS keys
vaultpack keygen --out mykey --algo ecdsa-p256
vaultpack keygen --out mykey --algo rsa-pss-4096

# Protect + sign in one step (algo is auto-detected from the key)
vaultpack protect --in config.json --sign --signing-priv signing.key

# Verify signature (algo is auto-detected from manifest and key)
vaultpack verify --in config.json.vpack --pubkey signing.pub

# Pipeline: encrypt from stdin, decrypt to stdout
cat config.json | vaultpack protect --stdin --out config.vpack --key-out config.key
vaultpack decrypt --in config.vpack --key config.key --stdout > config.json
```

## Install

### From source

Requires Go 1.22+.

```bash
git clone https://github.com/Skpow1234/Vaultpack.git
cd Vaultpack
go build -o bin/vaultpack ./cmd/vaultpack
```

The binary is at `bin/vaultpack`. Move it somewhere on your `$PATH`.

### With `go install`

```bash
go install github.com/Skpow1234/Vaultpack/cmd/vaultpack@latest
```

### Docker

```bash
docker build -t vaultpack .
docker run --rm -v "$PWD:/work" vaultpack protect --in /work/config.json
```

## Usage

### `protect` -- Encrypt a file into a `.vpack` bundle

```bash
vaultpack protect --in <file> [flags]
```

| Flag             | Default          | Description                                |
| ---------------- | ---------------- | ------------------------------------------ |
| `--in`           | (required)       | Input file to encrypt                      |
| `--out`          | `<input>.vpack`  | Output bundle path                         |
| `--key-out`      | `<input>.key`    | Path to write the generated key            |
| `--key`          |                  | Use an existing key (skips generation)     |
| `--aad`          |                  | Additional authenticated data              |
| `--cipher`       | `aes-256-gcm`    | AEAD cipher (see below)                    |
| `--hash-algo`    | `sha256`         | Hash algorithm for plaintext integrity     |
| `--sign`         |                  | Sign the bundle (algo auto-detected)       |
| `--signing-priv` |                  | Path to private signing key (with --sign)  |
| `--sign-algo`    |                  | Override signing algorithm (auto-detected) |
| `--password`     |                  | Encrypt with a password (instead of key)   |
| `--password-file`|                  | Read password from file                    |
| `--kdf`          | `argon2id`       | KDF: `argon2id`, `scrypt`, `pbkdf2-sha256` |
| `--kdf-time`     | `3`              | Argon2id time parameter                    |
| `--kdf-memory`   | `65536`          | Argon2id memory in KiB (64 MB default)     |
| `--recipient`    |                  | Recipient PEM public key (hybrid encrypt)  |
| `--stdin`        |                  | Read plaintext from standard input         |
| `--stdout`       |                  | Write bundle to standard output            |

When using `--password`, no key file is generated -- the key is derived from your password using the selected KDF. When using a key file, it is base64-encoded with a `b64:` prefix. Store either securely.

Supported ciphers (all use 32-byte keys and chunked streaming with 64 KB chunks):

| Cipher | Nonce | Notes |
| --- | --- | --- |
| `aes-256-gcm` (default) | 12 B | NIST standard, hardware-accelerated on most CPUs |
| `chacha20-poly1305` | 12 B | Excellent software performance, constant-time |
| `xchacha20-poly1305` | 24 B | Extended nonce eliminates nonce-reuse risk |

Decryption auto-detects the cipher from the bundle manifest.

### `decrypt` -- Decrypt a `.vpack` bundle

```bash
vaultpack decrypt --in <bundle> --out <file> --key <keyfile>
vaultpack decrypt --in <bundle> --out <file> --password "passphrase"
vaultpack decrypt --in <bundle> --out <file> --privkey recipient.key
```

| Flag              | Default    | Description                                        |
| ----------------- | ---------- | -------------------------------------------------- |
| `--in`            | (required) | Input `.vpack` bundle                              |
| `--out`           |            | Output plaintext path                              |
| `--key`           |            | Path to the symmetric decryption key               |
| `--password`      |            | Decrypt with a password                            |
| `--password-file` |            | Read password from file                            |
| `--privkey`       |            | Private key for hybrid decryption (PEM)            |
| `--aad`           |            | Override AAD from manifest                         |
| `--stdout`        |            | Write decrypted plaintext to standard output       |

Provide exactly one of `--key`, `--password`, or `--privkey`. The correct method is auto-detected from the manifest.

### `inspect` -- Show bundle metadata

```bash
vaultpack inspect --in <bundle> [--json]
```

Displays the manifest: version, input file info, hash, encryption parameters, and key fingerprint. Use `--json` for machine-readable output.

### `hash` -- Compute a file hash

```bash
vaultpack hash --in <file> [--algo sha256]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--in` | (required) | File to hash |
| `--algo` | `sha256` | Hash algorithm: `sha256`, `sha512`, `sha3-256`, `sha3-512`, `blake2b-256`, `blake2b-512`, `blake3` |

### `keygen` -- Generate a key pair

```bash
vaultpack keygen --out <prefix> [--algo ed25519]
```

| Flag     | Default    | Description                                            |
| -------- | ---------- | ------------------------------------------------------ |
| `--out`  | (required) | Output prefix (`<prefix>.key` + `<prefix>.pub`)        |
| `--algo` | `ed25519`  | Algorithm (see table below)                            |

Supported algorithms:

| Algorithm             | Purpose    | Notes                                      |
| --------------------- | ---------- | ------------------------------------------ |
| `ed25519`             | Signing    | Fast, compact (default)                    |
| `ecdsa-p256`          | Signing    | NIST P-256 curve                           |
| `ecdsa-p384`          | Signing    | NIST P-384 curve                           |
| `rsa-pss-2048`        | Signing    | RSA-PSS 2048-bit                           |
| `rsa-pss-4096`        | Signing    | RSA-PSS 4096-bit                           |
| `x25519-aes-256-gcm`  | Encryption | X25519 ECDH + HKDF + AES-256-GCM           |
| `ecies-p256`          | Encryption | ECIES with P-256 ECDH + HKDF               |
| `rsa-oaep-2048`       | Encryption | RSA-OAEP-SHA256 key wrapping (2048-bit)    |
| `rsa-oaep-4096`       | Encryption | RSA-OAEP-SHA256 key wrapping (4096-bit)    |

Keys are saved in PEM format (PKCS#8 private, PKIX public).

### `sign` -- Sign a `.vpack` bundle

```bash
vaultpack sign --in <bundle> --signing-priv <private-key>
```

| Flag             | Default    | Description                                             |
| ---------------- | ---------- | ------------------------------------------------------- |
| `--in`           | (required) | Input `.vpack` bundle to sign                           |
| `--signing-priv` | (required) | Path to private signing key                             |
| `--algo`         |            | Signing algorithm (auto-detected from key if omitted)   |

Adds a detached signature (`signature.sig`) to the bundle. The signing algorithm is auto-detected from the key format. The signature covers the canonical manifest and the SHA-256 of the payload, preventing both manifest tampering and payload swapping.

Supported signing algorithms:

| Algorithm         | Key Type       | Signature Format | Notes                            |
| ----------------- | -------------- | ---------------- | -------------------------------- |
| `ed25519`         | Ed25519        | Raw (64 bytes)   | Fast, compact, default           |
| `ecdsa-p256`      | ECDSA P-256    | ASN.1 DER        | NIST curve, widely supported     |
| `ecdsa-p384`      | ECDSA P-384    | ASN.1 DER        | Stronger NIST curve              |
| `rsa-pss-2048`    | RSA 2048-bit   | RSA-PSS/SHA-256  | Modern RSA padding               |
| `rsa-pss-4096`    | RSA 4096-bit   | RSA-PSS/SHA-256  | Higher security margin           |

### `verify` -- Verify a bundle signature

```bash
vaultpack verify --in <bundle> --pubkey <public-key>
```

Exits with code `0` if valid, `10` if verification fails.

### Global Flags

| Flag        | Description                  |
| ----------- | ---------------------------- |
| `--json`    | Output results as JSON       |
| `--quiet`   | Minimal output (errors only) |
| `--verbose` | Enable debug logging         |
| `--version` | Print version                |

## Bundle Format

A `.vpack` file is a ZIP archive containing:

```text
artifact.vpack
├── payload.bin        # ciphertext
├── manifest.json      # encryption params, hashes, metadata
└── signature.sig      # optional detached signature
```

## Security

- **Encryption**: AES-256-GCM, ChaCha20-Poly1305, or XChaCha20-Poly1305 (AEAD) with random nonces
- **Hashing**: SHA-256 (default), SHA-512, SHA3-256, SHA3-512, BLAKE2b-256, BLAKE2b-512, BLAKE3
- **Signing**: Ed25519, ECDSA (P-256/P-384), RSA-PSS (2048/4096) -- detached signatures over canonical manifest + payload hash
- **Key Derivation**: Argon2id (default, t=3, m=64MB, p=4), scrypt (N=32768, r=8, p=1), PBKDF2-SHA256 (600k iterations)
- **Hybrid Encryption**: X25519+HKDF+AES-256-GCM, ECIES-P256, RSA-OAEP-SHA256 (2048/4096)
- **Key fingerprint**: SHA-256 of the derived/raw key, stored in the manifest for early mismatch detection
- Ephemeral keys ensure forward secrecy for ECDH-based hybrid schemes
- Passwords, keys, and private keys are never stored inside the bundle

## Development

```bash
# Build
make build

# Test
make test

# Lint (requires golangci-lint)
make lint

# Format
make fmt

# Docker build
make docker-build
```

### Project Structure

```text
cmd/vaultpack/       # CLI entrypoint
internal/cli/        # Cobra command definitions
internal/crypto/     # AEAD, hashing, key management
internal/bundle/     # ZIP I/O, manifest read/write/validate
internal/util/       # Errors, encoding, exit codes
testdata/            # Test fixtures and golden files
```

## Exit Codes

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| `0`  | Success                                          |
| `1`  | Generic error                                    |
| `2`  | Invalid arguments                                |
| `10` | Verification failed                              |
| `11` | Decryption failed (wrong key / corrupted bundle) |
| `12` | Unsupported version or algorithm                 |
