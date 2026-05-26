package vaultpack

import (
	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// Manifest is the metadata stored inside a .vpack bundle.
//
// It is re-exported as a type alias of the canonical internal type so SDK
// consumers can use the same JSON field names as the CLI's --json output
// without any translation. The fields are documented in docs/design.md.
type Manifest = bundle.Manifest

// EncryptionMeta describes how the payload was encrypted.
type EncryptionMeta = bundle.EncryptionMeta

// PlaintextHash is the digest of the original plaintext.
type PlaintextHash = bundle.PlaintextHash

// CiphertextMeta is the size & layout of payload.bin.
type CiphertextMeta = bundle.CiphertextMeta

// InputMeta is the name + size of the original plaintext.
type InputMeta = bundle.InputMeta

// KeyID is the key fingerprint stored in the manifest.
type KeyID = bundle.KeyID

// KDFMeta describes a password-based key derivation.
type KDFMeta = bundle.KDFMeta

// HybridMeta describes hybrid (recipient-based) encryption.
type HybridMeta = bundle.HybridMeta

// CompressionMeta describes the compression algorithm (if any).
type CompressionMeta = bundle.CompressionMeta

// KeySplitMeta describes Shamir key splitting (if any).
type KeySplitMeta = bundle.KeySplitMeta

// RotationEntry records one M22 rotation/rewrap step in the bundle's lineage.
type RotationEntry = bundle.RotationEntry

// TransparencyEntry records an M24 Sigstore Rekor inclusion proof.
type TransparencyEntry = bundle.TransparencyEntry

// Bundle is the in-memory representation of a parsed .vpack file. It is what
// `Read` returns and `Write` accepts.
type Bundle struct {
	Manifest      *Manifest
	ManifestBytes []byte
	Ciphertext    []byte
	Signature     []byte // nil if the bundle is unsigned
}
