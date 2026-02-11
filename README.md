# VaultPack

A cross-platform CLI that encrypts, hashes, and signs data artifacts into portable `.vpack` bundles.

One tool. One bundle. Encryption + integrity + authenticity.

## Quick Start

```bash
# Encrypt a file (generates a key automatically)
vaultpack protect --in config.json

# Decrypt it
vaultpack decrypt --in config.json.vpack --out config.json --key config.json.key

# Inspect the bundle metadata
vaultpack inspect --in config.json.vpack

# Hash a file
vaultpack hash --in export.csv
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

| Flag        | Default          | Description                                        |
| ----------- | ---------------- | -------------------------------------------------- |
| `--in`      | (required)       | Input file to encrypt                              |
| `--out`     | `<input>.vpack`  | Output bundle path                                 |
| `--key-out` | `<input>.key`    | Path to write the generated key                    |
| `--key`     |                  | Use an existing key (skips generation)             |
| `--aad`     |                  | Additional authenticated data                      |

The key file is base64-encoded, prefixed with `b64:`. Store it securely -- without it, the bundle cannot be decrypted.

### `decrypt` -- Decrypt a `.vpack` bundle

```bash
vaultpack decrypt --in <bundle> --out <file> --key <keyfile>
```

| Flag    | Default    | Description                                          |
| ------- | ---------- | ---------------------------------------------------- |
| `--in`  | (required) | Input `.vpack` bundle                                |
| `--out` | (required) | Output plaintext path                                |
| `--key` | (required) | Path to the decryption key                           |
| `--aad` |            | Override AAD (defaults to value stored in manifest)  |

### `inspect` -- Show bundle metadata

```bash
vaultpack inspect --in <bundle> [--json]
```

Displays the manifest: version, input file info, hash, encryption parameters, and key fingerprint. Use `--json` for machine-readable output.

### `hash` -- Compute a file hash

```bash
vaultpack hash --in <file> [--algo sha256]
```

| Flag     | Default    | Description    |
| -------- | ---------- | -------------- |
| `--in`   | (required) | File to hash   |
| `--algo` | `sha256`   | Hash algorithm |

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

- **Encryption**: AES-256-GCM (AEAD) with random 12-byte nonces
- **Hashing**: SHA-256 over plaintext for integrity tracking
- **Key fingerprint**: SHA-256 of the raw key, stored in the manifest for early mismatch detection
- Keys are never stored inside the bundle

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
