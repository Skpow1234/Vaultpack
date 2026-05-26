package vaultpack

import (
	"bytes"
	stdcrypto "crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

// stdSigner is an alias for the stdlib crypto.Signer interface, used to avoid
// the package-name collision between stdlib "crypto" and the internal
// "github.com/Skpow1234/Vaultpack/internal/crypto" package within this file.
type stdSigner = stdcrypto.Signer

// ProtectOptions controls a single Protect call.
//
// Exactly one of {Plaintext, PlaintextReader, InputPath} must be set; this
// is the data that will be hashed and encrypted. Exactly one of {OutputPath,
// OutputWriter} must be set; this is where the resulting .vpack bundle is
// written.
//
// At most one of {Key, Password} may be set. If neither is supplied, a
// fresh 256-bit symmetric key is generated and returned in
// ProtectResult.GeneratedKey — the caller is responsible for persisting it
// somewhere durable before discarding the result.
type ProtectOptions struct {
	// Input: pick exactly one.
	Plaintext       []byte
	PlaintextReader io.Reader
	InputPath       string

	// InputName overrides the manifest's input.name. If empty, derived from
	// InputPath (basename) or defaults to "stdin".
	InputName string

	// Output: pick exactly one.
	OutputPath   string
	OutputWriter io.Writer

	// Mode: pick at most one.
	Key      []byte // raw symmetric key (32 bytes for AES-256, ChaCha20)
	Password string // PBKDF-derived key

	// KDF options. Used only when Password is set. Defaults to argon2id with
	// recommended parameters when empty.
	KDFAlgo string // "argon2id" | "scrypt" | "pbkdf2-sha256"

	// Cipher defaults to "aes-256-gcm". Supported: aes-256-gcm,
	// chacha20-poly1305, xchacha20-poly1305, aes-256-gcm-siv.
	Cipher string

	// ChunkSize defaults to 64 KiB. Larger chunks reduce per-chunk overhead
	// but use more memory; recommended max is 1 MiB.
	ChunkSize int

	// HashAlgo defaults to "sha256". Supported: sha256, sha512, blake3.
	HashAlgo string

	// AAD is additional authenticated data bound to every chunk. Optional.
	AAD []byte

	// Sign, when non-nil, asks Protect to embed a detached signature. The
	// signing algorithm is auto-detected from SigningKey unless Algo is set.
	Sign *SignParams
}

// SignParams configures Protect's optional signing step.
type SignParams struct {
	// PrivateKey is a PEM-encoded private key (PKCS#8) or, for ed25519, the
	// legacy raw 32-byte seed. Exactly one of PrivateKey / PrivateKeyPath
	// must be set.
	PrivateKey     []byte
	PrivateKeyPath string

	// Algo overrides the auto-detected signing algorithm. Optional.
	Algo string
}

// ProtectResult is what Protect returns on success.
type ProtectResult struct {
	Manifest *Manifest

	// BundlePath is the file the bundle was written to (only set when
	// OutputPath was used).
	BundlePath string

	// BundleBytes holds the .vpack bytes when OutputWriter was nil and the
	// caller buffered output to memory by setting OutputPath = "" along with
	// OutputWriter — currently always empty; reserved for a future
	// in-memory convenience.
	BundleBytes []byte

	// GeneratedKey is populated only when ProtectOptions.Key and
	// ProtectOptions.Password were both empty (the SDK generated a fresh
	// key). The caller MUST store this key somewhere durable before
	// discarding the result; it cannot be recovered.
	GeneratedKey []byte

	// SignatureAlgo and Signature are populated when ProtectOptions.Sign was
	// supplied. Signature is also embedded in the bundle.
	SignatureAlgo string
	Signature     []byte
}

// Protect encrypts the supplied plaintext and writes a .vpack bundle.
// See ProtectOptions for the supported modes and required fields.
func Protect(opts ProtectOptions) (*ProtectResult, error) {
	plaintextReader, inputName, inputSize, cleanup, err := resolveInput(opts)
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	if opts.Key != nil && opts.Password != "" {
		return nil, errors.New("vaultpack.Protect: Key and Password are mutually exclusive")
	}
	if opts.OutputPath == "" && opts.OutputWriter == nil {
		return nil, errors.New("vaultpack.Protect: OutputPath or OutputWriter is required")
	}

	cipherName := opts.Cipher
	if cipherName == "" {
		cipherName = crypto.CipherAES256GCM
	}
	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = crypto.DefaultChunkSize
	}
	hashAlgo := opts.HashAlgo
	if hashAlgo == "" {
		hashAlgo = "sha256"
	}
	if !crypto.SupportedHashAlgo(hashAlgo) {
		return nil, fmt.Errorf("vaultpack.Protect: unsupported hash algo %q", hashAlgo)
	}

	// Tee the plaintext: one branch hashes, the other buffers for the
	// streaming AEAD pass. The bundle format requires both the plaintext
	// hash and the ciphertext, so buffering the plaintext in memory is
	// expected for the SDK's v0.1 surface.
	var plaintextBuf bytes.Buffer
	hashReader := io.TeeReader(plaintextReader, &plaintextBuf)
	digest, err := crypto.HashReader(hashReader, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.Protect: hash plaintext: %w", err)
	}
	if inputSize < 0 {
		inputSize = int64(plaintextBuf.Len())
	}

	// Resolve the encryption key.
	key, kdfMeta, generated, err := resolveKey(opts)
	if err != nil {
		return nil, err
	}

	// Encrypt.
	var ciphertextBuf bytes.Buffer
	streamResult, err := crypto.EncryptStream(&plaintextBuf, &ciphertextBuf, key, opts.AAD, chunkSize, cipherName)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.Protect: encrypt: %w", err)
	}

	// Build manifest.
	keyAlgo, keyDigest := crypto.KeyFingerprint(key)
	var aadB64 *string
	if opts.AAD != nil {
		s := util.B64Encode(opts.AAD)
		aadB64 = &s
	}
	csCopy := chunkSize
	encMeta := bundle.EncryptionMeta{
		AEAD:      cipherName,
		NonceB64:  util.B64Encode(streamResult.BaseNonce),
		TagB64:    util.B64Encode(streamResult.LastTag),
		AADB64:    aadB64,
		ChunkSize: &csCopy,
		KDF:       kdfMeta,
		KeyID: bundle.KeyID{
			Algo:      keyAlgo,
			DigestB64: keyDigest,
		},
	}

	manifestVer := bundle.ManifestVersionV1
	if kdfMeta != nil {
		// V1 already supports KDF; bumping to V2 only when we use one of the
		// truly V2-only features. Keeping symmetry with the CLI.
	}

	m := &bundle.Manifest{
		Version:   manifestVer,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Input: bundle.InputMeta{
			Name: inputName,
			Size: inputSize,
		},
		Plaintext: bundle.PlaintextHash{
			Algo:      hashAlgo,
			DigestB64: util.B64Encode(digest),
		},
		Encryption: encMeta,
		Ciphertext: bundle.CiphertextMeta{
			Size: streamResult.CiphertextSize,
		},
	}

	manifestBytes, err := bundle.MarshalManifest(m)
	if err != nil {
		return nil, fmt.Errorf("vaultpack.Protect: marshal manifest: %w", err)
	}

	// Optional signing step.
	var sig []byte
	var resolvedSignAlgo string
	if opts.Sign != nil {
		sig, resolvedSignAlgo, manifestBytes, err = signManifest(opts.Sign, m, &ciphertextBuf)
		if err != nil {
			return nil, err
		}
	}

	// Write the bundle.
	wp := &bundle.WriteParams{
		Ciphertext:    ciphertextBuf.Bytes(),
		ManifestBytes: manifestBytes,
		Signature:     sig,
	}
	if opts.OutputWriter != nil {
		wp.Writer = opts.OutputWriter
	} else {
		wp.OutputPath = opts.OutputPath
	}
	if err := bundle.Write(wp); err != nil {
		return nil, fmt.Errorf("vaultpack.Protect: write bundle: %w", err)
	}

	res := &ProtectResult{
		Manifest:      m,
		BundlePath:    opts.OutputPath,
		SignatureAlgo: resolvedSignAlgo,
		Signature:     sig,
	}
	if generated {
		res.GeneratedKey = key
	}
	return res, nil
}

// --- internal helpers ---

func resolveInput(opts ProtectOptions) (io.Reader, string, int64, func(), error) {
	switch {
	case opts.Plaintext != nil:
		name := opts.InputName
		if name == "" {
			name = "memory"
		}
		return bytes.NewReader(opts.Plaintext), name, int64(len(opts.Plaintext)), nil, nil
	case opts.PlaintextReader != nil:
		name := opts.InputName
		if name == "" {
			name = "stream"
		}
		// Size unknown; manifest will be populated after buffering.
		return opts.PlaintextReader, name, -1, nil, nil
	case opts.InputPath != "":
		f, err := os.Open(opts.InputPath)
		if err != nil {
			return nil, "", 0, nil, fmt.Errorf("vaultpack.Protect: open input: %w", err)
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, "", 0, nil, fmt.Errorf("vaultpack.Protect: stat input: %w", err)
		}
		name := opts.InputName
		if name == "" {
			name = filepath.Base(opts.InputPath)
		}
		cleanup := func() { f.Close() }
		return f, name, info.Size(), cleanup, nil
	default:
		return nil, "", 0, nil, errors.New("vaultpack.Protect: one of Plaintext / PlaintextReader / InputPath is required")
	}
}

func resolveKey(opts ProtectOptions) (key []byte, kdfMeta *bundle.KDFMeta, generated bool, err error) {
	switch {
	case opts.Password != "":
		kdfAlgo := opts.KDFAlgo
		if kdfAlgo == "" {
			kdfAlgo = crypto.KDFArgon2id
		}
		kdfParams, err := crypto.DefaultKDFParams(kdfAlgo)
		if err != nil {
			return nil, nil, false, fmt.Errorf("vaultpack.Protect: kdf params: %w", err)
		}
		salt, err := crypto.GenerateKDFSalt()
		if err != nil {
			return nil, nil, false, fmt.Errorf("vaultpack.Protect: kdf salt: %w", err)
		}
		kdfParams.SaltB64 = util.B64Encode(salt)
		key, err := crypto.DeriveKey([]byte(opts.Password), salt, kdfParams, crypto.AES256KeySize)
		if err != nil {
			return nil, nil, false, fmt.Errorf("vaultpack.Protect: derive key: %w", err)
		}
		return key, &bundle.KDFMeta{
			Algo:       kdfParams.Algo,
			SaltB64:    kdfParams.SaltB64,
			Time:       kdfParams.Time,
			Memory:     kdfParams.Memory,
			Threads:    kdfParams.Threads,
			N:          kdfParams.N,
			R:          kdfParams.R,
			P:          kdfParams.P,
			Iterations: kdfParams.Iterations,
		}, false, nil

	case opts.Key != nil:
		if len(opts.Key) != crypto.AES256KeySize {
			return nil, nil, false, fmt.Errorf("vaultpack.Protect: Key must be %d bytes, got %d", crypto.AES256KeySize, len(opts.Key))
		}
		k := make([]byte, len(opts.Key))
		copy(k, opts.Key)
		return k, nil, false, nil

	default:
		// Generate a fresh DEK.
		k, err := crypto.GenerateKey(crypto.AES256KeySize)
		if err != nil {
			return nil, nil, false, fmt.Errorf("vaultpack.Protect: generate key: %w", err)
		}
		return k, nil, true, nil
	}
}

func signManifest(sp *SignParams, m *bundle.Manifest, ciphertextBuf *bytes.Buffer) (sig []byte, algo string, manifestBytes []byte, err error) {
	if sp.PrivateKey == nil && sp.PrivateKeyPath == "" {
		return nil, "", nil, errors.New("vaultpack.Protect: Sign requires PrivateKey or PrivateKeyPath")
	}
	if sp.PrivateKey != nil && sp.PrivateKeyPath != "" {
		return nil, "", nil, errors.New("vaultpack.Protect: PrivateKey and PrivateKeyPath are mutually exclusive")
	}

	var (
		signer   stdSigner
		detected string
	)
	if sp.PrivateKeyPath != "" {
		signer, detected, err = crypto.LoadPrivateKey(sp.PrivateKeyPath)
		if err != nil {
			return nil, "", nil, fmt.Errorf("vaultpack.Protect: load signing key: %w", err)
		}
	} else {
		signer, detected, err = crypto.ParsePrivateKey(sp.PrivateKey)
		if err != nil {
			return nil, "", nil, fmt.Errorf("vaultpack.Protect: parse signing key: %w", err)
		}
	}

	algo = detected
	if sp.Algo != "" {
		if sp.Algo != detected {
			return nil, "", nil, fmt.Errorf("vaultpack.Protect: Algo %q does not match key type %q", sp.Algo, detected)
		}
		algo = sp.Algo
	}

	m.SignatureAlgo = &algo
	ts := time.Now().UTC().Format(time.RFC3339)
	m.SignedAt = &ts

	canonical, err := bundle.CanonicalManifest(m)
	if err != nil {
		return nil, "", nil, fmt.Errorf("vaultpack.Protect: canonicalize manifest: %w", err)
	}
	payloadHash, err := crypto.HashReader(bytes.NewReader(ciphertextBuf.Bytes()), "sha256")
	if err != nil {
		return nil, "", nil, fmt.Errorf("vaultpack.Protect: hash payload: %w", err)
	}
	sigMsg := crypto.BuildSigningMessage(canonical, payloadHash)
	sig, err = crypto.SignMessage(signer, algo, sigMsg)
	if err != nil {
		return nil, "", nil, fmt.Errorf("vaultpack.Protect: sign: %w", err)
	}

	manifestBytes, err = bundle.MarshalManifest(m)
	if err != nil {
		return nil, "", nil, fmt.Errorf("vaultpack.Protect: re-marshal manifest: %w", err)
	}
	return sig, algo, manifestBytes, nil
}
