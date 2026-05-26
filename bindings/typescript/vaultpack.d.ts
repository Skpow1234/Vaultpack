/**
 * TypeScript type definitions for the VaultPack WASM module.
 *
 * After `await go.run(instance)`, `globalThis.Vaultpack` is populated with
 * the methods declared below. Every method is synchronous from JavaScript's
 * perspective and returns a plain object containing an `ok` field.
 *
 *   import "./vaultpack-loader.js";        // installs globalThis.Vaultpack
 *   const v = (globalThis as any).Vaultpack as Vaultpack;
 *
 * For richer typing in your project, copy this file alongside the wasm and
 * declare `const Vaultpack: Vaultpack`.
 */

/** Reply when an SDK call fails. */
export interface VaultpackError {
  ok: false;
  error: string;
}

/** Reply when an SDK call succeeds. */
export interface VaultpackSuccess<T> {
  ok: true;
  /** Any additional fields documented per-call. */
  manifest?: unknown;
  bundle?: Uint8Array;
  plaintext?: Uint8Array;
  generatedKey?: Uint8Array;
  signature?: Uint8Array;
  algorithm?: string;
  signedAt?: string;
  valid?: boolean;
  // Extra fields for forward-compatibility.
  [k: string]: unknown;
}

export type VaultpackReply<T = unknown> = VaultpackSuccess<T> | VaultpackError;

export interface ProtectOptions {
  /** Plaintext bytes to encrypt. */
  plaintext: Uint8Array;
  /** Optional 32-byte symmetric key. */
  key?: Uint8Array;
  /** Optional password (mutually exclusive with `key`). */
  password?: string;
  /** AEAD cipher name; defaults to "aes-256-gcm". */
  cipher?: string;
  /** Optional manifest input.name override. */
  inputName?: string;
  /** Additional authenticated data bound to every chunk. */
  aad?: Uint8Array;
}

export interface DecryptOptions {
  /** .vpack bundle bytes. */
  bundle: Uint8Array;
  /** Optional 32-byte symmetric key. */
  key?: Uint8Array;
  /** Optional password. */
  password?: string;
  /** Optional AAD that matches what Protect used. */
  aad?: Uint8Array;
}

export interface SignOptions {
  /** .vpack bundle bytes to sign. */
  bundle: Uint8Array;
  /** PEM-encoded private key (PKCS#8) or legacy ed25519-priv:<b64>. */
  privateKeyPEM: string;
  /** Optional algo override (auto-detected from the key otherwise). */
  algo?: string;
}

export interface VerifyOptions {
  /** .vpack bundle bytes to verify. */
  bundle: Uint8Array;
  /** PEM-encoded public key (PKIX) or legacy ed25519-pub:<b64>. */
  publicKeyPEM: string;
}

export interface Vaultpack {
  /** Returns the libvaultpack semver. */
  version(): string;
  /** Encrypt plaintext into a .vpack bundle. */
  protect(opts: ProtectOptions): VaultpackReply;
  /** Decrypt a .vpack bundle. */
  decrypt(opts: DecryptOptions): VaultpackReply;
  /** Parse the manifest from a .vpack bundle without decrypting. */
  inspect(bundle: Uint8Array): VaultpackReply;
  /** Sign a .vpack bundle, returning the resigned bundle. */
  sign(opts: SignOptions): VaultpackReply;
  /** Verify a signed .vpack bundle. */
  verify(opts: VerifyOptions): VaultpackReply;
}

declare global {
  // eslint-disable-next-line no-var
  var Vaultpack: Vaultpack;
}

export {};
