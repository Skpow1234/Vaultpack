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
vaultpack protect --in config.json --cipher aes-256-gcm-siv

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

# KMS: wrap DEK with AWS, GCP, Azure, or mock (no key file written; DEK never stored in plaintext)
vaultpack protect --in config.json --out config.vpack --kms-provider aws --kms-key-id alias/my-key
vaultpack decrypt --in config.vpack --out config.json --kms-provider aws
# GCP: key ID = full resource name (projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY)
vaultpack protect --in config.json --out config.vpack --kms-provider gcp --kms-key-id "projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey"
# Azure: key ID = full key URL (https://VAULT.vault.azure.net/keys/KEYNAME[/version])
vaultpack protect --in config.json --out config.vpack --kms-provider azure --kms-key-id "https://myvault.vault.azure.net/keys/mykey"
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

# Key rotation & rewrap (M22)
vaultpack rewrap          --in data.vpack --kms-provider aws --from-kms-key-id arn:aws:kms:... --to-kms-key-id arn:aws:kms:...
vaultpack rotate-key      --in data.vpack --old-key data.key --new-key-out data.new.key
vaultpack add-recipient   --in data.vpack --privkey alice.key --recipient bob.pub
vaultpack remove-recipient --in data.vpack --recipient bob.pub

# Cloud storage: read/write directly from Azure, AWS S3, GCS, or HTTPS
vaultpack protect --in az://mycontainer/data.csv --out az://mycontainer/data.vpack --azure-account mystorageaccount
vaultpack protect --in s3://mybucket/data.csv     --out s3://mybucket/data.vpack     --aws-region us-east-1
vaultpack protect --in gs://mybucket/data.csv     --out gs://mybucket/data.vpack
vaultpack inspect --in https://example.com/release.vpack   # HTTPS is read-only

# Cloud batch operations (any of az://, s3://, gs://)
vaultpack batch-protect --dir s3://mybucket/exports/ --out-dir s3://mybucket/encrypted/ --aws-region us-east-1
vaultpack batch-decrypt --dir gs://mybucket/encrypted/ --out-dir gs://mybucket/decrypted/ --key batch.key

# Pipeline: encrypt from stdin, decrypt to stdout
cat config.json | vaultpack protect --stdin --out config.vpack --key-out config.key
vaultpack decrypt --in config.vpack --key config.key --stdout > config.json
```

## Install

Pre-built binaries are published for **Linux** (amd64, arm64), **macOS** (amd64, arm64), and **Windows** (amd64, arm64) on [**Releases**](https://github.com/Skpow1234/Vaultpack/releases). Each release includes checksums and SBOMs for supply-chain verification.

### One-command install (curl)

Replace `VERSION` with a tag (e.g. `v1.0.0`) or use `latest` for the latest release.

```bash
# Linux (amd64)
curl -sL https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-linux-amd64.tar.gz | tar xz
sudo mv vaultpack /usr/local/bin/

# Linux (arm64)
curl -sL https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-linux-arm64.tar.gz | tar xz
sudo mv vaultpack /usr/local/bin/

# macOS (Apple Silicon)
curl -sL https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-darwin-arm64.tar.gz | tar xz
sudo mv vaultpack /usr/local/bin/

# macOS (Intel)
curl -sL https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-darwin-amd64.tar.gz | tar xz
sudo mv vaultpack /usr/local/bin/
```

**Windows:** download `vaultpack-windows-amd64.zip` or `vaultpack-windows-arm64.zip` from Releases, extract, and add the folder to your `PATH`.

### Package managers

```bash
# Homebrew (macOS / Linux) — once the tap is published
brew install Skpow1234/tap/vaultpack

# Chocolatey (Windows) — once the package is published
choco install vaultpack

# Debian / Ubuntu (.deb) and Red Hat / Fedora (.rpm) — direct download
curl -sLO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack_<version>_linux_amd64.deb
sudo dpkg -i vaultpack_<version>_linux_amd64.deb

curl -sLO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack_<version>_linux_amd64.rpm
sudo rpm -ivh vaultpack_<version>_linux_amd64.rpm

# Alpine Linux (.apk)
curl -sLO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack_<version>_linux_amd64.apk
sudo apk add --allow-untrusted vaultpack_<version>_linux_amd64.apk
```

> `.deb` / `.rpm` / `.apk` artifacts are produced by [`nfpm`](https://nfpm.goreleaser.com/) inside the goreleaser pipeline. A hosted apt/yum repository (Cloudsmith) can be enabled by setting `CLOUDSMITH_API_KEY` in the release workflow secrets.

### Verify checksums

Before installing, verify the archive with the published SHA-256 checksums:

```bash
curl -sLO https://github.com/Skpow1234/Vaultpack/releases/latest/download/checksums-sha256.txt
curl -sLO https://github.com/Skpow1234/Vaultpack/releases/latest/download/vaultpack-linux-amd64.tar.gz
sha256sum -c checksums-sha256.txt --ignore-missing
```

On macOS use `shasum -a 256 -c checksums-sha256.txt --ignore-missing`.

### Verify cosign signatures (Sigstore keyless)

Release artifacts and the SHA-256 checksum file are signed with [cosign](https://docs.sigstore.dev/) using **keyless signing** against the public Sigstore transparency log (Fulcio + Rekor). Each archive ships with a sidecar signature (`*.sig`) and certificate (`*.pem`).

```bash
ARCHIVE=vaultpack-linux-amd64.tar.gz
BASE=https://github.com/Skpow1234/Vaultpack/releases/latest/download
curl -sLO $BASE/$ARCHIVE
curl -sLO $BASE/$ARCHIVE.sig
curl -sLO $BASE/$ARCHIVE.pem

cosign verify-blob \
  --certificate $ARCHIVE.pem \
  --signature $ARCHIVE.sig \
  --certificate-identity-regexp 'https://github.com/Skpow1234/Vaultpack' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  $ARCHIVE
```

A successful run prints `Verified OK`. The same procedure applies to `checksums-sha256.txt` and any other release artifact.

### Upgrade

To upgrade, download the new version for your platform from [Releases](https://github.com/Skpow1234/Vaultpack/releases), verify the checksum, then replace the existing binary (or re-run the one-command install and overwrite `/usr/local/bin/vaultpack`). With `go install`, run `go install github.com/Skpow1234/Vaultpack/cmd/vaultpack@latest` again.

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

Images are built for **linux/amd64** and **linux/arm64**. Use the published image or build locally:

```bash
# Run from registry (when published)
docker run --rm -v "$PWD:/work" ghcr.io/Skpow1234/vaultpack:latest protect --in /work/config.json

# Build locally (single arch)
docker build -t vaultpack .
docker run --rm -v "$PWD:/work" vaultpack protect --in /work/config.json
```

Multi-arch build: `make docker-buildx` or `docker buildx build --platform linux/amd64,linux/arm64 -t vaultpack:tag .`

### Security considerations

- **Checksums:** Always verify `checksums-sha256.txt` against the downloaded archive before installing.
- **SBOM:** Releases include CycloneDX SBOMs (e.g. `vaultpack-linux-amd64.tar.gz.sbom.json`) for dependency and supply-chain review.
- **Cosign signatures:** All release artifacts are signed with cosign keyless (Sigstore) — see the verification snippet above. Signatures (`*.sig`) and certificates (`*.pem`) are published alongside each archive and the checksum file.

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
| `--kms-provider` |                  | KMS provider: `aws`, `gcp`, `azure`, `mock` (or from config) |
| `--kms-key-id`   |                  | KMS key ID: AWS alias/ARN; GCP full resource name; Azure key URL; `mock-key-id` for mock |
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
| `aes-256-gcm-siv` | 12 B | Nonce-misuse-resistant AEAD (RFC 8452); safer when nonce uniqueness can't be guaranteed |

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
vaultpack inspect --in <bundle> [--json] [--redact]
```

Displays the manifest: version, input file info, hash, encryption parameters, and key fingerprint. Use `--json` for machine-readable output. Use `--redact` to omit sensitive fields (plaintext digest, nonces, tags, key IDs, recipient fingerprints, wrapped DEKs, KDF salt, etc.) so the output is safe to share for support or audit.

### `diff` -- Compare two bundles' manifests

```bash
vaultpack diff --a <bundle1> --b <bundle2> [--ignore-time] [--ignore-nonce] [--json]
```

Compares the two manifests field-by-field (plaintext hash, AEAD, key ID, scheme, recipients, signature, etc.). Exit code is **0** when the manifests are identical and **10** when differences are found. Use `--ignore-time` to skip `created_at` / `signed_at` and `--ignore-nonce` to skip per-encryption values (nonce, tag, ephemeral key, wrapped DEK) — useful when comparing two protections of the same plaintext.

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
| `ed448`               | Signing    | RFC 8032 Edwards curve over Goldilocks (higher security margin) |
| `ecdsa-p256`          | Signing    | NIST P-256 curve                           |
| `ecdsa-p384`          | Signing    | NIST P-384 curve                           |
| `rsa-pss-2048`        | Signing    | RSA-PSS 2048-bit                           |
| `rsa-pss-4096`        | Signing    | RSA-PSS 4096-bit                           |
| `ml-dsa-65`           | Signing    | NIST FIPS 204 ML-DSA (post-quantum)        |
| `ml-dsa-87`           | Signing    | NIST FIPS 204 ML-DSA (post-quantum)        |
| `slh-dsa-128s`        | Signing    | NIST FIPS 205 SLH-DSA (SPHINCS+, post-quantum, hash-based) |
| `x25519-aes-256-gcm`  | Encryption | X25519 ECDH + HKDF + AES-256-GCM           |
| `ecies-p256`          | Encryption | ECIES with P-256 ECDH + HKDF               |
| `rsa-oaep-2048`       | Encryption | RSA-OAEP-SHA256 key wrapping (2048-bit)    |
| `rsa-oaep-4096`       | Encryption | RSA-OAEP-SHA256 key wrapping (4096-bit)    |
| `ml-kem-768`          | Encryption | NIST FIPS 203 ML-KEM (post-quantum)        |
| `ml-kem-1024`         | Encryption | NIST FIPS 203 ML-KEM (post-quantum)        |

Keys are saved in PEM format (PKCS#8 private, PKIX public; ML-KEM, ML-DSA, and Ed448 use custom PEM block types).

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
| `ed448`           | Ed448 (RFC 8032)| Raw (114 bytes) | Edwards curve over Goldilocks, higher security margin |
| `ecdsa-p256`      | ECDSA P-256    | ASN.1 DER        | NIST curve, widely supported     |
| `ecdsa-p384`      | ECDSA P-384    | ASN.1 DER        | Stronger NIST curve              |
| `rsa-pss-2048`    | RSA 2048-bit   | RSA-PSS/SHA-256  | Modern RSA padding               |
| `rsa-pss-4096`    | RSA 4096-bit   | RSA-PSS/SHA-256  | Higher security margin           |
| `ml-dsa-65`       | ML-DSA-65      | FIPS 204         | Post-quantum (NIST)              |
| `ml-dsa-87`       | ML-DSA-87      | FIPS 204         | Post-quantum (NIST)              |
| `slh-dsa-128s`    | SLH-DSA-SHA2-128s | FIPS 205      | Post-quantum hash-based (SPHINCS+); large sigs |

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

### Cloud storage (Azure, S3, GCS, HTTPS)

VaultPack accepts cloud URIs anywhere a local path is allowed for `--in` / `--out` (and `--dir` / `--out-dir` for batch operations). Bundles are downloaded to a private temp file, processed locally, and re-uploaded — so all crypto runs in-process on local data.

| Scheme    | Backend                | Read | Write | Default credential chain                                                         |
| --------- | ---------------------- | ---- | ----- | -------------------------------------------------------------------------------- |
| `az://`   | Azure Blob Storage     | yes  | yes   | Connection string → `azidentity.DefaultAzureCredential` (managed identity, CLI)  |
| `s3://`   | AWS S3                 | yes  | yes   | AWS SDK v2 default chain (env, shared config, IAM role, EC2 IMDSv2)              |
| `gs://`   | Google Cloud Storage   | yes  | yes   | Google Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud)  |
| `https://`, `http://` | Generic HTTP  | yes  | **no** | Optional `VAULTPACK_HTTP_BEARER` or `VAULTPACK_HTTP_USER`/`VAULTPACK_HTTP_PASS` |

```bash
# Azure
vaultpack protect --in az://container/in.csv --out az://container/out.vpack --azure-account myaccount

# AWS S3
vaultpack protect --in s3://mybucket/in.csv  --out s3://mybucket/out.vpack --aws-region us-east-1

# Google Cloud Storage
vaultpack protect --in gs://mybucket/in.csv  --out gs://mybucket/out.vpack

# HTTPS read-only (e.g. fetching a release bundle)
vaultpack inspect --in https://example.com/release.vpack
vaultpack verify  --in https://example.com/release.vpack --pubkey publisher.pub
```

**URI formats**

- `az://container/path/to/blob`
- `s3://bucket/path/to/object`
- `gs://bucket/path/to/object`
- `https://host/path` or `http://host/path`

**CLI flags**

| Flag                        | Description                                                                       |
| --------------------------- | --------------------------------------------------------------------------------- |
| `--azure-account`           | Azure storage account (or `AZURE_STORAGE_ACCOUNT` env)                            |
| `--azure-connection-string` | Azure connection string (or `AZURE_STORAGE_CONNECTION_STRING` env)                |
| `--aws-region`              | AWS region for `s3://` (or `AWS_REGION` / `AWS_DEFAULT_REGION` env)               |
| `--aws-profile`             | AWS shared config profile (or `AWS_PROFILE` env)                                  |
| `--s3-endpoint`             | Override S3 endpoint URL (MinIO, LocalStack, S3-compatible services)              |
| `--s3-path-style`           | Use path-style S3 addressing (required by some S3-compatible services)            |

> GCS uses Application Default Credentials only; no flags are needed beyond the standard ADC env vars / `gcloud auth application-default login`.

### Key rotation & rewrap

VaultPack supports four rotation operations for the data encryption key (DEK)
of a bundle. Each one clears any prior signature on the manifest (since the
manifest changes) — re-sign with `vaultpack sign` afterward.

| Command              | Payload re-encrypted? | DEK changes? | Use case                                                                  |
| -------------------- | --------------------- | ------------ | ------------------------------------------------------------------------- |
| `rewrap`             | no                    | no           | Rotate the **KMS key** that wraps the DEK. Fast; no plaintext access.     |
| `rotate-key`         | **yes**               | yes          | Rotate after suspected DEK compromise, or to fully revoke a recipient.    |
| `add-recipient`      | no                    | no           | Wrap the existing DEK for additional public-key recipients.               |
| `remove-recipient`   | no                    | no           | Drop a recipient entry from the manifest. Combine with `rotate-key` for full revocation. |

```bash
# Rotate the KMS key wrapping the DEK (payload untouched)
vaultpack rewrap --in data.vpack \
    --kms-provider aws \
    --from-kms-key-id arn:aws:kms:us-east-1:111111111111:key/old \
    --to-kms-key-id   arn:aws:kms:us-east-1:111111111111:key/new

# Full DEK rotation (re-encrypts payload under fresh DEK)
vaultpack rotate-key --in data.vpack --old-key data.key --new-key-out data.new.key
vaultpack rotate-key --in data.vpack --old-password "old" --new-password "new"
vaultpack rotate-key --in data.vpack --kms-provider aws   # reuses same KMS key id
vaultpack rotate-key --in data.vpack --old-privkey alice.key --recipient alice.pub --recipient bob.pub

# Add a recipient to an existing bundle
vaultpack add-recipient --in data.vpack \
    --privkey alice.key \
    --recipient bob.pub --recipient carol.pub

# Remove a recipient (does NOT re-encrypt; the DEK is unchanged)
vaultpack remove-recipient --in data.vpack --recipient bob.pub
# To fully revoke bob, follow with rotate-key:
vaultpack rotate-key --in data.vpack --old-privkey alice.key --recipient alice.pub --recipient carol.pub
```

Every rotation appends a `rotated_from` entry to the manifest with:

- `operation` — one of `rewrap`, `rotate-key`, `add-recipient`, `remove-recipient`,
- `rotated_at` — RFC 3339 timestamp,
- `bundle_hash` — SHA-256 of the previous bundle bytes, providing a tamper-evident lineage,
- `notes` — context such as old/new KMS key IDs or count of added/removed recipients.

`vaultpack inspect` displays the full chain.

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
| `--policy`  | Policy file (YAML/JSON/Rego) enforced before ops (or `VAULTPACK_POLICY` env) |
| `--version` | Print version                |

**Transparency flags** (`sign`, `verify`, `attest`):

| Flag                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `--transparency`        | Upload signature to a Rekor transparency log                 |
| `--rekor-url`           | Rekor base URL (defaults to `https://rekor.sigstore.dev`)    |
| `--keyless`             | Use Fulcio for keyless signing (sign only; requires `--transparency`) |
| `--fulcio-url`          | Fulcio base URL (defaults to `https://fulcio.sigstore.dev`)  |
| `--oidc-token-file`     | Path to OIDC ID token file (or `VAULTPACK_OIDC_TOKEN` / `SIGSTORE_ID_TOKEN` env) |
| `--check-transparency`  | Verify Rekor inclusion + SET signature during `verify`       |
| `--rekor-pubkey`        | PEM-encoded Rekor public key (offline verify)                |

### Transparency & Public Verifiability (Sigstore)

VaultPack can upload bundle signatures to a [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log, giving every signed bundle a publicly-auditable, tamper-evident record. The Rekor metadata is embedded in the manifest so verifiers can validate the inclusion proof offline against a copy of Rekor's public key.

**Sign with a personal key + Rekor:**

```bash
vaultpack sign --in artifact.vpack --signing-priv id.key \
  --transparency \
  --rekor-url https://rekor.sigstore.dev    # default if omitted
```

**Sign keyless via Fulcio (OIDC):**

```bash
# Acquire an OIDC ID token (CI workloads usually mount one automatically;
# locally you can use `gh auth token`, `gcloud auth print-identity-token`, etc.)
export SIGSTORE_ID_TOKEN=$(cat my-oidc.jwt)

vaultpack sign --in artifact.vpack \
  --keyless \
  --transparency \
  --rekor-url https://rekor.sigstore.dev \
  --fulcio-url https://fulcio.sigstore.dev
```

Keyless mode generates a fresh ECDSA P-256 keypair, presents it to Fulcio along with the OIDC token, receives a short-lived signing certificate, signs the bundle with the ephemeral key, and uploads the signature + cert chain to Rekor.

**Verify with transparency:**

```bash
vaultpack verify --in artifact.vpack --pubkey id.pub \
  --check-transparency                              # online: fetches Rekor pubkey
# or, fully offline:
vaultpack verify --in artifact.vpack --pubkey id.pub \
  --check-transparency \
  --rekor-pubkey rekor.pub
```

The verifier checks that:

1. The bundle's existing detached signature is valid against `--pubkey`.
2. For each `transparency` entry in the manifest:
   - The Rekor-stored data hash equals SHA-256 of the canonical signing message we just rebuilt.
   - The Rekor-stored signature equals the bundle's `signature.sig` byte-for-byte.
   - The Rekor SET (Signed Entry Timestamp) is a valid signature by the log's published key.

**Algorithm support:** Rekor verifies signatures server-side using stdlib `crypto/x509`. VaultPack therefore restricts `--transparency` to `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-pss-2048`, and `rsa-pss-4096`. Post-quantum algos (`ml-dsa-*`, `slh-dsa-*`, `ed448`) are rejected with a clear error.

`attest --transparency` mirrors the flow for the SLSA provenance artifact: VaultPack signs `provenance.json` with the supplied key and uploads a hashedrekord entry; the Rekor UUID is printed but is *not* embedded in the manifest (use `sign --transparency` for that).

### Policy & RBAC

VaultPack can gate every operation (protect, decrypt, inspect, verify, sign,
attest, rewrap, rotate-key, add/remove-recipient) through a policy file. The
policy is resolved in this order: `--policy <path>` → `VAULTPACK_POLICY` env →
`policy_file:` in `.vpack.yaml`. When no policy is configured, every operation
runs as before.

**YAML policy example** (`./policy.yaml`):

```yaml
version: 1
default: allow            # what to do when no rule matches
rules:
  - name: block-dev-keys-in-prod
    action: deny
    reason: "dev KMS keys cannot be decrypted from prod"
    when:
      operation: [decrypt, rewrap]
      kms_key_id_matches: ".*/dev-.*"

  - name: deny-unsigned-decrypts
    action: deny
    reason: "decrypts require a signature"
    when:
      operation: [decrypt]
      is_signed: false

  - name: after-hours
    action: deny
    reason: "no decrypts between 00:00 and 06:00 UTC"
    when:
      operation: [decrypt]
      time_window: {from: "00:00", to: "06:00", timezone: "UTC"}

  - name: alice-only-prod-keys
    action: allow
    when:
      operation: [decrypt]
      user: alice
      kms_key_id_matches: ".*/prod-.*"
```

Supported `when:` predicates (all ANDed within a rule):

| Field                       | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| `operation`                 | List of op names (`decrypt`, `verify`, …)                 |
| `user` / `user_matches`     | Principal username (exact or regex)                      |
| `hostname` / `hostname_matches` | Host (exact or regex)                                |
| `weekday`                   | List of day names (`Saturday`, `Sunday`, …)              |
| `time_window`               | `{from, to, timezone}` HH:MM range (wraps over midnight) |
| `bundle_path_matches`       | Regex on the bundle path                                 |
| `kms_key_id` / `kms_key_id_matches` | KMS Key ID exact or regex                        |
| `cipher_in`                 | List of allowed AEAD names                               |
| `hybrid_scheme_matches`     | Regex on the hybrid KEM scheme                           |
| `signature_algo_in` / `signature_algo_not_in` | List of allowed/forbidden signature algos |
| `is_signed`                 | Bool: rule fires only if signature presence matches      |
| `recipient_fingerprint_in`  | List of recipient fingerprints                           |
| `plaintext_digest_in`       | List of plaintext SHA-256 digests (base64)               |
| `min_recipients` / `max_recipients` | Recipient-count bounds                            |

**JSON** is supported too — just use a `.json` file with the same field names.

**Rego (OPA)** is loaded automatically for `.rego` files. The package should
expose an `allow` rule and an optional `deny_reason`:

```rego
package vaultpack

default allow = false

allow {
    input.operation == "decrypt"
    input.user == "alice"
    startswith(input.manifest.kms_key_id, "arn:aws:kms:us-east-1:")
}

deny_reason = sprintf("user %q cannot decrypt %q", [input.user, input.manifest.kms_key_id]) {
    not allow
}
```

The Rego `input` mirrors the native context: `operation`, `user`, `hostname`,
`bundle_path`, `weekday`, `now`, and (when available) a `manifest` object with
`aead`, `kms_key_id`, `plaintext_digest`, `signature_algo`, `signed`,
`hybrid_scheme`, `recipient_count`, `recipient_fingerprints`.

**Policy commands:**

```bash
vaultpack policy validate --file policy.yaml
vaultpack policy test     --file policy.yaml --bundle secret.vpack --op decrypt --user alice
vaultpack policy show     --policy policy.yaml
```

Every policy denial is recorded in the audit log as a `policy-deny` entry with
the offending operation, matched rule name, and reason.

## Service Mode (`vaultpack serve`)

`vaultpack serve` runs a long-running HTTP API exposing the SDK to remote
clients over the network. The wire contract is the same JSON envelope as
the C-shared library and WASM bindings, so a single set of client code can
target all three transports.

```bash
# Local development (no auth — refuses unless --auth-disabled is set):
vaultpack serve --listen :8443 --auth-disabled

# Production with bearer-token auth + TLS:
vaultpack serve \
  --listen :8443 \
  --auth-token "$(cat /etc/vaultpack/token)" \
  --tls-cert /etc/ssl/vaultpack.crt \
  --tls-key  /etc/ssl/vaultpack.key

# Production with mTLS only (no bearer):
vaultpack serve --listen :8443 \
  --tls-cert server.crt --tls-key server.key \
  --tls-client-ca client-ca.pem

# UNIX socket for sidecar deployments:
vaultpack serve --listen unix:/run/vaultpack.sock --auth-disabled
```

### Endpoints

All endpoints are POST and consume/produce `application/json` unless noted.
Every reply has shape `{"ok": true|false, ...}`.

| Method | Path             | Purpose                                |
|--------|------------------|----------------------------------------|
| GET    | `/healthz`       | Liveness probe (no auth, no metrics)   |
| GET    | `/metrics`       | Prometheus text exposition (no auth)   |
| GET    | `/v1/version`    | SDK + API version                      |
| POST   | `/v1/protect`    | Encrypt → bundle                       |
| POST   | `/v1/decrypt`    | Decrypt bundle                         |
| POST   | `/v1/inspect`    | Decode manifest                        |
| POST   | `/v1/sign`       | Add/replace detached signature         |
| POST   | `/v1/verify`     | Verify detached signature              |

See [`docs/openapi.yaml`](docs/openapi.yaml) for the full OpenAPI 3.1 spec
including every request/response schema.

### Example: end-to-end round-trip with `curl`

```bash
TOKEN="$(cat /etc/vaultpack/token)"

# Encrypt some plaintext, get the bundle + generated key back.
RESPONSE=$(curl -s -X POST https://vp.example.com/v1/protect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext_b64":"aGVsbG8gd29ybGQ="}')
BUNDLE=$(jq -r .bundle_b64 <<< "$RESPONSE")
KEY=$(jq -r .generated_key_b64 <<< "$RESPONSE")

# Decrypt it again.
curl -s -X POST https://vp.example.com/v1/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg b "$BUNDLE" --arg k "$KEY" '{bundle_b64:$b, key_b64:$k}')" \
  | jq -r .plaintext_b64 | base64 -d
```

### Authentication

The server refuses to start unless at least one of the following is true:

- `--auth-token <secret>` is set (constant-time bearer check on every request).
- `--tls-client-ca <ca.pem>` is set (mutual TLS — client cert required).
- `--auth-disabled` is set (explicit opt-out for local dev only).

Tokens can also be read from a file with `--auth-token-file`, which is
recommended in container environments to keep the secret out of the process
argv.

### KMS unwrap cache

When the server decrypts bundles wrapped by a KMS, it caches the unwrap
result in memory keyed by `(provider, key-id, wrapped-DEK)` for
`--kms-cache-ttl` (default 5 m). The cache is bounded by
`--kms-cache-size` (default 1024 entries; FIFO eviction). Hits, misses,
evictions, and current size are exported as Prometheus metrics:

```
vaultpack_kms_cache_entries 42
vaultpack_kms_cache_hits_total 1289
vaultpack_kms_cache_misses_total 51
vaultpack_kms_cache_evicted_total 0
```

### Observability

`GET /metrics` returns a Prometheus 0.0.4 text exposition with:

- `vaultpack_build_info{version}`         — gauge constant 1.
- `vaultpack_uptime_seconds`              — counter.
- `vaultpack_http_requests_total{path,status}` — counter per endpoint.
- `vaultpack_http_request_duration_seconds` — histogram per endpoint
  (`{le="0.005"}…{le="+Inf"}`, `_sum`, `_count`).
- `vaultpack_auth_denied_total`           — counter.
- `vaultpack_kms_cache_*`                 — see above.

## SDK & Language Bindings

VaultPack ships with first-class libraries for Go, Python, and JavaScript so
you can encrypt, decrypt, sign, verify, and inspect `.vpack` bundles
programmatically without spawning the CLI.

### Go SDK (`pkg/vaultpack`)

The Go SDK is **semver-stable** (current version `vaultpack.Version`) and
re-exports the same bundle/manifest types the CLI uses, so JSON shapes
match byte-for-byte.

```go
import "github.com/Skpow1234/Vaultpack/pkg/vaultpack"

// Encrypt with a generated key.
res, err := vaultpack.Protect(vaultpack.ProtectOptions{
    InputPath:  "secret.txt",
    OutputPath: "secret.vpack",
})
if err != nil { log.Fatal(err) }
os.WriteFile("secret.key", res.GeneratedKey, 0o600)

// Decrypt.
dec, err := vaultpack.Decrypt(vaultpack.DecryptOptions{
    InputPath:  "secret.vpack",
    OutputPath: "secret.out",
    Key:        keyBytes,
})
```

| Function                                  | Purpose                              |
|-------------------------------------------|--------------------------------------|
| `Protect(opts) (*ProtectResult, error)`   | Encrypt file or `[]byte` → bundle    |
| `Decrypt(opts) (*DecryptResult, error)`   | Decrypt bundle → file or `[]byte`    |
| `Inspect(path) (*Manifest, error)`        | Decode manifest only                 |
| `InspectBytes(b) (*Manifest, error)`      | In-memory manifest decode            |
| `SignBundle(opts) (*SignResult, error)`   | Add/replace detached signature       |
| `SignBytes(b, opts) ([]byte, *SignResult, error)` | In-memory variant            |
| `Verify(opts) (*VerifyResult, error)`     | Verify detached signature            |
| `VerifyBytes(b, opts) (*VerifyResult, error)`     | In-memory variant            |

Supported modes in v0.1: symmetric key (auto-generated or supplied),
password (argon2id / scrypt / pbkdf2), and detached signatures (ed25519 /
ecdsa / rsa-pss / ml-dsa / slh-dsa). Hybrid (recipient) encryption, KMS
wrapping, key splitting, compression, and Sigstore transparency uploads
remain CLI-only for now and will be added in future minor releases.

### Native shared library (C-shared)

`cmd/vaultpack-c` builds VaultPack as a `libvaultpack.{so,dylib,dll}`
exposing a tiny JSON-in/JSON-out C ABI usable from any language with a C
FFI. Build:

```bash
go build -buildmode=c-shared -tags cshared \
  -o libvaultpack.so ./cmd/vaultpack-c
```

The `cshared` build tag excludes the package from default `go build ./...`
runs so the rest of the repo continues to build without cgo or a C
toolchain. See `cmd/vaultpack-c/README.md` for the full per-OS reference.

### Python (`bindings/python`)

```bash
pip install vaultpack          # ships with no native code
export VAULTPACK_LIB=/path/to/libvaultpack.so
```

```python
import base64, vaultpack
res = vaultpack.protect(input_path="secret.txt", output_path="secret.vpack")
key = base64.b64decode(res["generated_key_b64"])
out = vaultpack.decrypt(input_path="secret.vpack", key=key)
print(out["manifest"]["input"]["name"])
```

### TypeScript / WebAssembly (`bindings/typescript`)

```bash
# Build the WASM artifact (Go 1.22+).
GOOS=js GOARCH=wasm go build -o vaultpack.wasm ./cmd/vaultpack-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" bindings/typescript/
```

```javascript
import { loadVaultpack } from "@vaultpack/wasm";
const Vaultpack = await loadVaultpack(
  new URL("./vaultpack.wasm", import.meta.url),
);
const enc = Vaultpack.protect({ plaintext: new TextEncoder().encode("hi") });
const dec = Vaultpack.decrypt({ bundle: enc.bundle, key: enc.generatedKey });
console.log(new TextDecoder().decode(dec.plaintext));
```

The full TypeScript surface lives in `bindings/typescript/vaultpack.d.ts`.

### Semver policy

The public Go SDK at `pkg/vaultpack/` and the `.vpack` on-disk format
follow [Semantic Versioning 2.0.0](https://semver.org/). New fields with
`omitempty` and new option values whose default matches today's behavior
are minor-release additions; renames, removals, and behavior changes
require a major bump. Internal packages (`internal/...`) are not covered
by this guarantee.

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
- **Signing**: Ed25519, Ed448 (RFC 8032), ECDSA (P-256/P-384), RSA-PSS (2048/4096), ML-DSA-65/87 (FIPS 204, post-quantum), SLH-DSA-128s (FIPS 205 / SPHINCS+, post-quantum hash-based)
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
- **KMS (DEK wrap)**: optional `--kms-provider` (aws, gcp, azure, mock) wraps the DEK with a KMS key; only the wrapped ciphertext and key ID are stored; no key file is written; decrypt unwraps automatically with `--kms-provider`. AWS uses symmetric CMK + encryption context; GCP uses symmetric CryptoKey + AAD; Azure uses Key Vault RSA-OAEP-256 wrap
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
internal/plugin/     # Plugin discovery and subprocess KEM/sign adapters
testdata/            # Test fixtures and golden files
examples/            # Example plugins (e.g. plugin-dummy-kem)
```

### Plugins

You can add custom KEM schemes and signature algorithms via **plugins**: executables discovered from `VPACK_PLUGIN_DIR` or config `plugin_dir`. Plugin scheme names appear in `keygen --algo`, `protect --recipient`, and decrypt/sign/verify. See **[docs/plugins.md](docs/plugins.md)** for the contract and **[examples/plugin-dummy-kem](examples/plugin-dummy-kem)** for a minimal example.

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
