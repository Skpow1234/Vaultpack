// Package aesgcmsiv implements AES-GCM-SIV as specified in RFC 8452.
//
// AES-GCM-SIV is a nonce misuse-resistant authenticated encryption with
// associated data (AEAD) algorithm. Unlike standard AES-GCM, it does not
// fail catastrophically if a nonce is accidentally reused - it only reveals
// whether two messages with the same nonce are identical.
//
// This implementation uses only Go's standard library (crypto/aes, crypto/cipher).
//
// This package is derived from github.com/fernandezvara/aesgcmsiv (MIT licensed,
// (c) Alvaro Fernandez Vara) and vendored here to keep the Go toolchain
// requirement aligned with the rest of this module.
package aesgcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	// NonceSize is the size of an AES-GCM-SIV nonce in bytes.
	NonceSize = 12

	// TagSize is the size of an AES-GCM-SIV authentication tag in bytes.
	TagSize = 16

	// MaxPlaintextSize is the maximum plaintext size in bytes (2^36).
	MaxPlaintextSize = 1 << 36

	// MaxAdditionalDataSize is the maximum additional data size in bytes (2^36).
	MaxAdditionalDataSize = 1 << 36

	blockSize = aes.BlockSize // 16 bytes
)

var (
	// ErrOpen is returned when decryption fails due to authentication failure.
	ErrOpen = errors.New("aesgcmsiv: message authentication failed")

	// ErrInvalidKeySize is returned when the key is not 16 or 32 bytes.
	ErrInvalidKeySize = errors.New("aesgcmsiv: invalid key size, must be 16 or 32 bytes")
)

// AEAD represents an AES-GCM-SIV cipher implementing cipher.AEAD.
type AEAD struct {
	keyGenKey []byte // Key-generating key
	is256     bool   // true for AES-256, false for AES-128
}

// New creates a new AES-GCM-SIV AEAD cipher.
// The key must be either 16 bytes (for AES-128-GCM-SIV) or 32 bytes (for AES-256-GCM-SIV).
func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case 16, 32:
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		return &AEAD{
			keyGenKey: keyCopy,
			is256:     len(key) == 32,
		}, nil
	default:
		return nil, ErrInvalidKeySize
	}
}

// NonceSize returns the size of the nonce that must be passed to Seal and Open.
func (a *AEAD) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *AEAD) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated slice.
func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("aesgcmsiv: incorrect nonce length")
	}
	if uint64(len(plaintext)) > MaxPlaintextSize {
		panic("aesgcmsiv: plaintext too large")
	}
	if uint64(len(additionalData)) > MaxAdditionalDataSize {
		panic("aesgcmsiv: additional data too large")
	}

	authKey, encKey := a.deriveKeys(nonce)
	tag := a.computeTag(authKey, encKey, nonce, plaintext, additionalData)

	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagSize)
	a.aesCTR(encKey, tag, plaintext, ciphertext[:len(plaintext)])
	copy(ciphertext[len(plaintext):], tag)

	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice.
func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("aesgcmsiv: incorrect nonce length")
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	if uint64(len(ciphertext)) > MaxPlaintextSize+TagSize {
		panic("aesgcmsiv: ciphertext too large")
	}
	if uint64(len(additionalData)) > MaxAdditionalDataSize {
		panic("aesgcmsiv: additional data too large")
	}

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertextWithoutTag := ciphertext[:len(ciphertext)-TagSize]

	authKey, encKey := a.deriveKeys(nonce)

	ret, plaintext := sliceForAppend(dst, len(ciphertextWithoutTag))
	a.aesCTR(encKey, tag, ciphertextWithoutTag, plaintext)

	expectedTag := a.computeTag(authKey, encKey, nonce, plaintext, additionalData)

	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, ErrOpen
	}

	return ret, nil
}

// deriveKeys derives the message authentication key and message encryption key
// from the key-generating key and nonce as specified in RFC 8452 Section 4.
func (a *AEAD) deriveKeys(nonce []byte) (authKey, encKey []byte) {
	block, _ := aes.NewCipher(a.keyGenKey)

	var numBlocks int
	if a.is256 {
		numBlocks = 6
	} else {
		numBlocks = 4
	}

	authKey = make([]byte, 16)
	if a.is256 {
		encKey = make([]byte, 32)
	} else {
		encKey = make([]byte, 16)
	}

	input := make([]byte, blockSize)
	output := make([]byte, blockSize)

	for i := 0; i < numBlocks; i++ {
		binary.LittleEndian.PutUint32(input[0:4], uint32(i))
		copy(input[4:], nonce)
		block.Encrypt(output, input)

		switch {
		case i < 2:
			copy(authKey[i*8:], output[:8])
		default:
			copy(encKey[(i-2)*8:], output[:8])
		}
	}

	return authKey, encKey
}

// computeTag computes the authentication tag using POLYVAL as specified in RFC 8452.
func (a *AEAD) computeTag(authKey, encKey, nonce, plaintext, additionalData []byte) []byte {
	var s [16]byte

	polyvalUpdate(s[:], authKey, additionalData)
	polyvalUpdate(s[:], authKey, plaintext)

	var lengthBlock [16]byte
	binary.LittleEndian.PutUint64(lengthBlock[0:8], uint64(len(additionalData))*8)
	binary.LittleEndian.PutUint64(lengthBlock[8:16], uint64(len(plaintext))*8)
	polyvalBlock(s[:], authKey, lengthBlock[:])

	for i := 0; i < NonceSize; i++ {
		s[i] ^= nonce[i]
	}
	s[15] &= 0x7f

	encBlock, _ := aes.NewCipher(encKey)
	tag := make([]byte, 16)
	encBlock.Encrypt(tag, s[:])

	return tag
}

func polyvalUpdate(s []byte, h []byte, data []byte) {
	for len(data) >= blockSize {
		polyvalBlock(s, h, data[:blockSize])
		data = data[blockSize:]
	}
	if len(data) > 0 {
		var padded [blockSize]byte
		copy(padded[:], data)
		polyvalBlock(s, h, padded[:])
	}
}

// polyvalBlock performs: s = dot(s + block, h) where dot(a,b) = a * b * x^(-128)
func polyvalBlock(s []byte, h []byte, block []byte) {
	for i := 0; i < 16; i++ {
		s[i] ^= block[i]
	}
	polyvalMul(s, h)
}

// polyvalMul performs: s = dot(s, h) = s * h * x^(-128) in the POLYVAL field
// POLYVAL uses polynomial x^128 + x^127 + x^126 + x^121 + 1
func polyvalMul(s []byte, h []byte) {
	var product [16]byte
	var v [16]byte
	copy(v[:], h)

	for i := 0; i < 128; i++ {
		byteIdx := i / 8
		bitIdx := uint(i % 8)

		if (s[byteIdx]>>bitIdx)&1 == 1 {
			for j := 0; j < 16; j++ {
				product[j] ^= v[j]
			}
		}

		carry := (v[15] >> 7) & 1
		for j := 15; j > 0; j-- {
			v[j] = (v[j] << 1) | (v[j-1] >> 7)
		}
		v[0] = v[0] << 1

		if carry == 1 {
			v[0] ^= 0x01
			v[15] ^= 0xc2
		}
	}

	var result [16]byte
	copy(v[:], product[:])

	for i := 0; i < 128; i++ {
		// x^(-128) = x^127 + x^124 + x^121 + x^114 + 1
		xinv128Bit := uint8(0)
		switch i {
		case 0, 114, 121, 124, 127:
			xinv128Bit = 1
		}

		if xinv128Bit == 1 {
			for j := 0; j < 16; j++ {
				result[j] ^= v[j]
			}
		}

		if i < 127 {
			carry := (v[15] >> 7) & 1
			for j := 15; j > 0; j-- {
				v[j] = (v[j] << 1) | (v[j-1] >> 7)
			}
			v[0] = v[0] << 1
			if carry == 1 {
				v[0] ^= 0x01
				v[15] ^= 0xc2
			}
		}
	}

	copy(s, result[:])
}

func (a *AEAD) aesCTR(encKey, tag, src, dst []byte) {
	if len(src) == 0 {
		return
	}

	block, _ := aes.NewCipher(encKey)

	var counter [16]byte
	copy(counter[:], tag)
	counter[15] |= 0x80

	var keystream [blockSize]byte
	for i := 0; i < len(src); i += blockSize {
		block.Encrypt(keystream[:], counter[:])

		end := i + blockSize
		if end > len(src) {
			end = len(src)
		}

		for j := i; j < end; j++ {
			dst[j] = src[j] ^ keystream[j-i]
		}

		ctr := binary.LittleEndian.Uint32(counter[:4])
		binary.LittleEndian.PutUint32(counter[:4], ctr+1)
	}
}

func sliceForAppend(dst []byte, n int) (ret, slice []byte) {
	if cap(dst) >= len(dst)+n {
		ret = dst[:len(dst)+n]
	} else {
		ret = make([]byte, len(dst)+n)
		copy(ret, dst)
	}
	slice = ret[len(dst):]
	return
}
