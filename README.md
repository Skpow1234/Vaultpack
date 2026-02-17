# VaultPack

[![CI](https://github.com/Skpow1234/Vaultpack/actions/workflows/ci.yml/badge.svg)](https://github.com/Skpow1234/Vaultpack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

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

# Compress before encrypting (gzip or zstd)
vaultpack protect --in large.csv --compress zstd
vaultpack protect --in archive.tar --compress gzip

# Encrypt for a recipient's public key (hybrid encryption)
vaultpack keygen --out alice --algo x25519-aes-256-gcm
vaultpack protect --in config.json --recipient alice.pub
vaultpack decrypt --in config.json.vpack --out config.json --privkey alice.key

# Post-quantum: ML-KEM for encryption, ML-DSA for signing
vaultpack keygen --out pq --algo ml-kem-768
vaultpack protect --in config.json --recipient pq.pub
vaultpack keygen --out signpq --algo ml-dsa-65
vaultpack sign --in config.json.vpack --signing-priv signpq.key

# Encrypt for multiple recipients
vaultpack protect --in config.json --recipient alice.pub --recipient bob.pub

# KMS: wrap DEK with AWS KMS or mock (no key file written; DEK never stored in plaintext)
vaultpack protect --in config.json --out config.vpack --kms-provider aws --kms-key-id alias/my-key
vaultpack decrypt --in config.vpack --out config.json --kms-provider aws
# For tests: --kms-provider mock --kms-key-id mock-key-id

# Inspect the bundle metadata
vaultpack inspect --in config.json.vpack

# Verify end-to-end integrity (decrypt + re-hash + compare)
vaultpack verify-integrity --in config.json.vpack --key config.json.key

# Hash a file (default: SHA-256; also supports sha512, sha3-256, sha3-512, blake2b-256, blake2b-512, blake3)
vaultpack hash --in export.csv
vaultpack hash --in export.csv --algo blake3

# Generate a signing key pair (default: Ed25519)
vaultpack keygen --out signing

# Generate ECDSA, RSA-PSS, or post-quantum (ML-DSA / ML-KEM) keys
vaultpack keygen --out mykey --algo ecdsa-p256
vaultpack keygen --out mykey --algo rsa-pss-4096
vaultpack keygen --out mykey --algo ml-dsa-65
vaultpack keygen --out mykey --algo ml-kem-768

# Protect + sign in one step (algo is auto-detected from the key)
vaultpack protect --in config.json --sign --signing-priv signing.key

# Verify signature (algo is auto-detected from manifest and key)
vaultpack verify --in config.json.vpack --pubkey signing.pub

# Protect + auto-split key into Shamir shares (3-of-5)
vaultpack protect --in config.json --split-shares 5 --split-threshold 3

# Split an existing key file into shares
vaultpack split-key --in config.json.key --shares 5 --threshold 3

# Reconstruct a key from any 3 shares
vaultpack combine-key --share config.json.key.share1 --share config.json.key.share3 --share config.json.key.share5 --out recovered.key

# Batch encrypt an entire directory (4 workers)
vaultpack batch-protect --dir ./exports/ --out-dir ./encrypted/ --workers 4

# Batch decrypt all .vpack bundles
vaultpack batch-decrypt --dir ./encrypted/ --out-dir ./decrypted/ --key ./encrypted/batch.key

# Batch inspect (summary of all bundles)
vaultpack batch-inspect --dir ./encrypted/

# Audit trail and integrity
vaultpack attest --in config.vpack --out provenance.json
vaultpack seal --dir ./bundles/ --out merkle-root.txt
vaultpack verify-seal --dir ./bundles/ --root $(cat merkle-root.txt)
vaultpack audit export --format csv --operation protect

# Azure Blob Storage: encrypt directly from/to Azure
vaultpack protect --in az://mycontainer/data.csv --out az://mycontainer/data.vpack --azure-account mystorageaccount
vaultpack decrypt --in az://mycontainer/data.vpack --out az://mycontainer/data.csv --key data.key --azure-account mystorageaccount

# Azure batch operations
vaultpack batch-protect --dir az://mycontainer/exports/ --out-dir az://mycontainer/encrypted/ --azure-account mystorageaccount
vaultpack batch-decrypt --dir az://mycontainer/encrypted/ --out-dir az://mycontainer/decrypted/ --key batch.key --azure-account mystorageaccount

# Pipeline: encrypt from stdin, decrypt to stdout
cat config.json | vaultpack protect --stdin --out config.vpack --key-out config.key
vaultpack decrypt --in config.vpack --key config.key --stdout > config.json
```

## Install

### Pre-built binaries (recommended)

Download the latest release for your platform from
[**Releases**](https://github.com/Skpow1234/Vaultpack/releases):

```bash
# Linux (amd64)
curl -LO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-linux-amd64
chmod +x vaultpack-linux-amd64
sudo mv vaultpack-linux-amd64 /usr/local/bin/vaultpack

# macOS (Apple Silicon)
curl -LO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-darwin-arm64
chmod +x vaultpack-darwin-arm64
sudo mv vaultpack-darwin-arm64 /usr/local/bin/vaultpack
```

Every release includes `checksums-sha256.txt` -- verify before installing.

### With `go install`

```bash
go install github.com/Skpow1234/Vaultpack/cmd/vaultpack@latest
```

### From source

Requires Go 1.22+.

```bash
git clone https://github.com/Skpow1234/Vaultpack.git
cd Vaultpack
go build -o bin/vaultpack ./cmd/vaultpack
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

| Flag             | Default          | Description                                                   |
| ---------------- | ---------------- | ------------------------------------------------------------- |
| `--in`           | (required)       | Input file to encrypt                                         |
| `--out`          | `<input>.vpack`  | Output bundle path                                            |
| `--key-out`      | `<input>.key`    | Path to write the generated key                               |
| `--key`          |                  | Use an existing key (skips generation)                        |
| `--aad`          |                  | Additional authenticated data                                 |
| `--cipher`       | `aes-256-gcm`    | AEAD cipher (see below)                                       |
| `--hash-algo`    | `sha256`         | Hash algorithm for plaintext integrity                        |
| `--sign`         |                  | Sign the bundle (algo auto-detected)                          |
| `--signing-priv` |                  | Path to private signing key (with --sign)                     |
| `--sign-algo`    |                  | Override signing algorithm (auto-detected)                    |
| `--password`     |                  | Encrypt with a password (instead of key)                      |
| `--password-file`|                  | Read password from file                                       |
| `--kdf`          | `argon2id`       | KDF: `argon2id`, `scrypt`, `pbkdf2-sha256`                    |
| `--kdf-time`     | `3`              | Argon2id time parameter                                       |
| `--kdf-memory`   | `65536`          | Argon2id memory in KiB (64 MB default)                        |
| `--recipient`    |                  | Recipient PEM public key (hybrid, repeatable)                 |
| `--compress`     | `none`           | Pre-encryption compression: `none`, `gzip`, `zstd`            |
| `--split-shares` |                  | Split key into N Shamir shares (requires `--split-threshold`) |
| `--split-threshold` |               | K: minimum shares to reconstruct the key                      |
| `--kms-provider` |                  | KMS provider for DEK wrap: `aws`, `mock` (or from config)      |
| `--kms-key-id`   |                  | KMS key ID (e.g. `alias/my-key` for AWS, `mock-key-id` for mock) |
| `--stdin`        |                  | Read plaintext from standard input                            |
| `--stdout`       |                  | Write bundle to standard output                               |

When using `--kms-provider` and `--kms-key-id`, a random DEK is generated, used to encrypt the payload, then wrapped by the KMS. Only the wrapped DEK and key ID are stored in the manifest; no key file is written. Decrypt with `--kms-provider` to unwrap the DEK automatically.

When using `--password`, no key file is generated -- the key is derived from your password using the selected KDF. When using a key file, it is base64-encoded with a `b64:` prefix. Store either securely.

Multiple `--recipient` flags enable multi-recipient encryption: one random DEK is generated and wrapped separately for each recipient. Each recipient can decrypt independently with their own private key.

When `--split-shares` and `--split-threshold` are set, the encryption key is split into N Shamir shares using GF(256) polynomial splitting. No single key file is written; instead, N share files are created. Reconstruct the key with `combine-key` before decrypting.

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
| `--kms-provider`  |            | KMS provider to unwrap DEK (when bundle has `kms_key_id`) |
| `--aad`           |            | Override AAD from manifest                         |
| `--stdout`        |            | Write decrypted plaintext to standard output       |

Provide exactly one of `--key`, `--password`, `--privkey`, or `--kms-provider` (when the bundle was encrypted with KMS). The correct method is auto-detected from the manifest.

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
| `ml-dsa-65`           | Signing    | NIST FIPS 204 ML-DSA (post-quantum)        |
| `ml-dsa-87`           | Signing    | NIST FIPS 204 ML-DSA (post-quantum)        |
| `x25519-aes-256-gcm`  | Encryption | X25519 ECDH + HKDF + AES-256-GCM           |
| `ecies-p256`          | Encryption | ECIES with P-256 ECDH + HKDF               |
| `rsa-oaep-2048`       | Encryption | RSA-OAEP-SHA256 key wrapping (2048-bit)    |
| `rsa-oaep-4096`       | Encryption | RSA-OAEP-SHA256 key wrapping (4096-bit)    |
| `ml-kem-768`          | Encryption | NIST FIPS 203 ML-KEM (post-quantum)        |
| `ml-kem-1024`         | Encryption | NIST FIPS 203 ML-KEM (post-quantum)        |

Keys are saved in PEM format (PKCS#8 private, PKIX public; ML-KEM and ML-DSA use custom PEM types).

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
| `ml-dsa-65`       | ML-DSA-65      | FIPS 204         | Post-quantum (NIST)              |
| `ml-dsa-87`       | ML-DSA-87      | FIPS 204         | Post-quantum (NIST)              |

### `verify` -- Verify a bundle signature

```bash
vaultpack verify --in <bundle> --pubkey <public-key>
```

Exits with code `0` if valid, `10` if verification fails.

### `verify-integrity` -- Decrypt and verify plaintext hash

```bash
vaultpack verify-integrity --in <bundle> --key <keyfile>
vaultpack verify-integrity --in <bundle> --password "pass"
vaultpack verify-integrity --in <bundle> --privkey recipient.key
```

Decrypts the bundle, re-hashes the recovered plaintext, and compares it with the `plaintext_hash` in the manifest. This confirms end-to-end integrity: the decrypted content matches what was originally protected. Exits `0` on match, `10` on mismatch.

### `split-key` -- Split a key into Shamir shares

```bash
vaultpack split-key --in <keyfile> --shares 5 --threshold 3
```

| Flag          | Default    | Description                                      |
| ------------- | ---------- | ------------------------------------------------ |
| `--in`        | (required) | Path to the key file to split                    |
| `--shares`    | `5`        | Total number of shares (N), range [2..255]       |
| `--threshold` | `3`        | Minimum shares to reconstruct (K), range [2..N]  |
| `--out-dir`   |            | Directory for share files (default: same as key) |

Produces N share files named `<keyfile>.share1` through `<keyfile>.shareN`. Each share encodes its index, threshold, total, and a checksum for tamper detection.

### `combine-key` -- Reconstruct a key from Shamir shares

```bash
vaultpack combine-key --share data.key.share1 --share data.key.share3 --share data.key.share5 --out data.key
```

| Flag      | Default    | Description                                         |
| --------- | ---------- | --------------------------------------------------- |
| `--share` | (required) | Path to a share file (repeat for each share)        |
| `--out`   | (required) | Output path for the reconstructed key               |

The threshold K is read from the share metadata. Provide at least K shares. Duplicate shares, tampered shares, and insufficient shares are detected and rejected.

### `batch-protect` -- Encrypt all files in a directory

```bash
vaultpack batch-protect --dir ./exports/ --out-dir ./encrypted/ [flags]
```

| Flag             | Default       | Description                                              |
| ---------------- | ------------- | -------------------------------------------------------- |
| `--dir`          | (required)    | Source directory to encrypt                              |
| `--out-dir`      | (required)    | Output directory for `.vpack` bundles                    |
| `--key-out`      | `<out-dir>/batch.key` | Path for the shared batch key                    |
| `--per-file-key` |               | Generate a unique key per file instead of a shared key   |
| `--cipher`       | `aes-256-gcm` | AEAD cipher                                              |
| `--hash-algo`    | `sha256`      | Hash algorithm                                           |
| `--compress`     | `none`        | Pre-encryption compression: `none`, `gzip`, `zstd`       |
| `--workers`      | `NumCPU`      | Number of parallel workers                               |
| `--include`      |               | Glob pattern for files to include (repeatable)           |
| `--exclude`      |               | Glob pattern for files to exclude (repeatable)           |
| `--dry-run`      |               | Preview which files would be processed                   |

Recursively encrypts all files, preserving directory structure. Writes a `batch-manifest.json` to the output directory listing every bundle with its status and duration. Individual file failures do not abort the batch; all errors are collected and reported at the end.

### `batch-decrypt` -- Decrypt all `.vpack` bundles in a directory

```bash
vaultpack batch-decrypt --dir ./encrypted/ --out-dir ./decrypted/ --key batch.key
```

| Flag              | Default    | Description                                        |
| ----------------- | ---------- | -------------------------------------------------- |
| `--dir`           | (required) | Source directory with `.vpack` bundles             |
| `--out-dir`       | (required) | Output directory for decrypted files               |
| `--key`           |            | Path to shared batch decryption key                |
| `--password`      |            | Decrypt with a password                            |
| `--password-file` |            | Read password from file                            |
| `--workers`       | `NumCPU`   | Number of parallel workers                         |

Auto-detects `.vpack` files recursively and strips the `.vpack` extension from output filenames. If no `--key` is provided, looks for per-file keys (`<bundle>.key`) alongside each bundle.

### `batch-inspect` -- Show summary of bundles in a directory

```bash
vaultpack batch-inspect --dir ./encrypted/ [--json]
```

Displays a summary of every `.vpack` bundle in the directory, including cipher, hash algorithm, and input file info. If a `batch-manifest.json` is present, its operation summary is also shown.

### Azure Blob Storage

VaultPack supports reading from and writing to Azure Blob Storage using the `az://` URI scheme.

```bash
# Encrypt a file from Azure, write the bundle back to Azure
vaultpack protect --in az://container/input.csv --out az://container/output.vpack --azure-account myaccount

# Decrypt a bundle from Azure
vaultpack decrypt --in az://container/output.vpack --out az://container/result.csv --key file.key --azure-account myaccount

# Inspect a bundle on Azure
vaultpack inspect --in az://container/output.vpack --azure-account myaccount

# Batch protect from Azure to Azure
vaultpack batch-protect --dir az://container/data/ --out-dir az://container/encrypted/ --azure-account myaccount

# Using a connection string instead
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net"
vaultpack protect --in az://container/file.csv --out az://container/file.vpack
```

**URI format**: `az://container/path/to/blob`

**Authentication** (in priority order):

1. `--azure-connection-string` flag or `AZURE_STORAGE_CONNECTION_STRING` env var
2. `azidentity.DefaultAzureCredential` (managed identity, env vars, Azure CLI token)

**Account resolution**: `--azure-account` flag or `AZURE_STORAGE_ACCOUNT` env var. Required when not using a connection string.

| Flag                        | Description                                                         |
| --------------------------- | ------------------------------------------------------------------- |
| `--azure-account`           | Azure storage account name (or `AZURE_STORAGE_ACCOUNT` env var)     |
| `--azure-connection-string` | Azure storage connection string (or `AZURE_STORAGE_CONNECTION_STRING` env var) |

### Audit trail and integrity

**Audit log**: Use `--audit-log <path>` or `VAULTPACK_AUDIT_LOG` to append a JSON-lines log of every operation (protect, decrypt, sign, verify, attest, seal, etc.). Each line includes timestamp, operation, input/output paths, key fingerprint, user, hostname, and success/error.

```bash
export VAULTPACK_AUDIT_LOG=/var/log/vaultpack-audit.jsonl
vaultpack protect --in data.csv --out data.vpack

# Export audit log to CSV or JSON (with optional filters)
vaultpack audit export --format csv --since 2026-01-01 --operation protect
vaultpack audit export --log /var/log/vaultpack-audit.jsonl --format json --key-fingerprint abc123
```

**Provenance (SLSA-style)**: Generate a provenance statement for a bundle (builder identity, build timestamp, source hash, environment).

```bash
vaultpack attest --in bundle.vpack --out provenance.json
vaultpack attest --in bundle.vpack --embed   # store provenance.json inside the bundle
```

**Merkle seal**: Create a Merkle root over all `.vpack` files in a directory; later verify that no bundles were added, removed, or modified.

```bash
vaultpack seal --dir ./bundles/ --out root.txt
vaultpack verify-seal --dir ./bundles/ --root $(cat root.txt)
```

| Command / flag      | Description                                                |
| ------------------- | ---------------------------------------------------------- |
| `--audit-log`       | Append-only audit log file (or `VAULTPACK_AUDIT_LOG` env)  |
| `vaultpack attest`  | Generate SLSA-style provenance for a bundle                |
| `vaultpack seal`    | Compute Merkle root over directory of .vpack files         |
| `vaultpack verify-seal` | Verify directory against a previously sealed root      |
| `vaultpack audit export` | Export audit log to CSV/JSON with filters             |

### Configuration (config file and profiles)

Optional config file and profiles let you set defaults for audit log, cipher, chunk size, output directory, and default recipients.

**Config file search order:** `--config` or `VPACK_CONFIG` env, then `~/.vpack.yaml`, then `./.vpack.yaml` (first found).

**Profile:** `--profile dev|staging|prod` or `VPACK_PROFILE` to apply profile-specific overrides from the config file.

**Precedence (highest wins):** CLI flags > environment variables > config file (and profile) > built-in defaults.

```bash
# Show effective configuration
vaultpack config
vaultpack config --json

# Use a config file and profile
vaultpack --config ./vpack.yaml --profile prod protect --in data.csv
export VPACK_CONFIG=~/.vpack.yaml VPACK_PROFILE=prod
vaultpack protect --in data.csv
```

**Config file keys (YAML):** `audit_log`, `cipher`, `chunk_size`, `output_dir`, `default_key_path`, `default_pubkey_path`, `recipients`. Under `profiles.<name>` you can override any of these (e.g. `profiles.prod.audit_log`).

### Global Flags

| Flag        | Description                  |
| ----------- | ---------------------------- |
| `--json`    | Output results as JSON       |
| `--quiet`   | Minimal output (errors only) |
| `--verbose` | Enable debug logging         |
| `--audit-log` | Audit log file path        |
| `--config`  | Config file path (or `VPACK_CONFIG` env) |
| `--profile` | Config profile: dev, staging, prod (or `VPACK_PROFILE` env) |
| `--version` | Print version                |

## Bundle Format

A `.vpack` file is a ZIP archive containing:

```text
artifact.vpack
├── payload.bin        # ciphertext
├── manifest.json      # encryption params, hashes, metadata
├── signature.sig      # optional detached signature
└── provenance.json    # optional SLSA-style provenance (from attest --embed)
```

## Security

### Algorithms

- **AEAD encryption**: AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305
- **Hashing**: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b-256, BLAKE2b-512, BLAKE3
- **Signing**: Ed25519, ECDSA (P-256/P-384), RSA-PSS (2048/4096), ML-DSA-65/87 (FIPS 204, post-quantum)
- **KDFs**: Argon2id (t=3, m=64 MB, p=4), scrypt (N=32768, r=8, p=1), PBKDF2-SHA256 (600k iter)
- **Hybrid encryption**: X25519+HKDF+AES-256-GCM, ECIES-P256, RSA-OAEP-SHA256, ML-KEM-768/1024 (FIPS 203, post-quantum)

### Chunked Streaming Encryption

All encryption uses chunked streaming (default 64 KB plaintext chunks). This is necessary for constant-memory processing of large files, but it means each chunk is a separate AEAD operation. VaultPack prevents the three standard attacks on chunked AEAD:

**Nonce derivation (prevents nonce reuse).**
A single random base nonce is generated per bundle. Each chunk's nonce is derived as `base_nonce XOR chunk_index`, where the chunk index is a big-endian 64-bit counter XORed into the last 8 bytes of the base nonce. Because the counter is monotonically increasing and the base nonce is random, no two chunks within a bundle (or across bundles) share a nonce with practical probability.

**Last-chunk flag (prevents truncation).**
The final chunk's counter has bit 63 set (`counter | 0x8000000000000000`). This means a truncated file (missing the last N chunks) will fail AEAD authentication on what the decryptor thinks is the final chunk, because the nonce won't match. An attacker cannot truncate the ciphertext without detection.

**Chunk ordering (prevents reordering).**
Because each chunk's nonce encodes its sequential index, swapping two chunks causes both to fail AEAD authentication -- the ciphertext was sealed under a different nonce than the one the decryptor derives for that position. Chunks cannot be reordered, duplicated, or removed.

**What is authenticated per chunk.**
Each AEAD `Seal`/`Open` call authenticates: (1) the chunk plaintext (confidentiality + integrity), (2) the nonce (implicitly, via the AEAD construction), and (3) optional AAD passed by the user via `--aad`. The AAD is the same for every chunk and is also stored in the manifest.

**What is authenticated across the bundle.**
The manifest records the base nonce, the authentication tag of the final chunk, the total ciphertext size, the cipher name, and the chunk size. When signing is used, the signature covers the canonical manifest and the SHA-256 of the full `payload.bin`, binding the manifest to the exact ciphertext byte-for-byte.

### Other Properties

- **Key fingerprint**: SHA-256 of the raw key is stored in the manifest for early wrong-key detection before attempting decryption
- **KMS (DEK wrap)**: optional `--kms-provider` (e.g. AWS KMS, mock) wraps the DEK with a KMS key; only the wrapped ciphertext and key ID are stored; no key file is written; decrypt unwraps automatically with `--kms-provider`
- **Multi-recipient**: one random DEK is generated and wrapped independently for each recipient
- **Forward secrecy**: ECDH-based hybrid schemes use ephemeral keys; compromising the recipient's long-term key does not reveal past DEKs
- **Compression**: optional pre-encryption gzip/zstd; data is compressed *before* encryption so the ciphertext reveals no compression-ratio side channel
- **Timestamps**: signing records an RFC 3339 UTC timestamp in the manifest (`signed_at`)
- **Shamir's Secret Sharing**: GF(256) polynomial splitting; K-of-N threshold with checksum-based tamper detection. Each byte is split independently; fewer than K shares reveal zero information
- **Batch operations**: parallel processing with configurable worker count, per-file or shared keys, glob include/exclude filters, dry-run preview, and `batch-manifest.json` for auditing
- **Manifest versioning**: v1 for basic bundles, v2 when using compression, multi-recipient, or key splitting (backward-compatible reader)
- **Azure Blob Storage**: native integration via `azblob` SDK; supports `DefaultAzureCredential` (managed identity, env vars, CLI token) and connection strings; blobs are downloaded to temp files for processing and cleaned up automatically
- **Audit trail**: append-only JSON-lines log of every operation (timestamp, operation, paths, key fingerprint, user, hostname, success/error); export to CSV/JSON with filters
- **Provenance**: SLSA-style attestation (builder, timestamp, source hash, environment); optional embedding in bundle
- **Merkle seal**: deterministic Merkle root over a directory of .vpack files; verify-seal detects any add/remove/modify
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
internal/azure/      # Azure Blob Storage client
internal/audit/      # Audit log, Merkle seal, provenance
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

## License

[MIT](LICENSE)
