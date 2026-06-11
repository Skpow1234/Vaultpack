package vaultpack

import (
	"github.com/Skpow1234/Vaultpack/internal/vpackop"
)

// Recipient identifies a hybrid-encryption recipient.
type Recipient = vpackop.Recipient

// Share is one Shamir share from Protect when SplitShares is set.
type Share = vpackop.Share

// CombineShares reconstructs a symmetric key from Shamir shares.
func CombineShares(shares [][]byte) ([]byte, error) {
	return vpackop.CombineShares(shares)
}

func toVpackopProtect(p ProtectOptions) vpackop.ProtectParams {
	params := vpackop.ProtectParams{
		Plaintext:       p.Plaintext,
		PlaintextReader: p.PlaintextReader,
		InputPath:       p.InputPath,
		InputName:       p.InputName,
		OutputPath:      p.OutputPath,
		OutputWriter:    p.OutputWriter,
		Key:             p.Key,
		Password:        p.Password,
		KDFAlgo:         p.KDFAlgo,
		KMSProvider:     p.KMSProvider,
		KMSKeyID:        p.KMSKeyID,
		Recipients:      p.Recipients,
		Compress:        p.Compress,
		SplitShares:     p.SplitShares,
		SplitThreshold:  p.SplitThreshold,
		Cipher:          p.Cipher,
		ChunkSize:       p.ChunkSize,
		HashAlgo:        p.HashAlgo,
		AAD:             p.AAD,
		ParallelWorkers: p.ParallelWorkers,
	}
	if p.Sign != nil {
		params.Sign = &vpackop.SignParams{
			PrivateKey:     p.Sign.PrivateKey,
			PrivateKeyPath: p.Sign.PrivateKeyPath,
			Algo:           p.Sign.Algo,
		}
	}
	return params
}

func fromVpackopProtect(r *vpackop.ProtectResult) *ProtectResult {
	if r == nil {
		return nil
	}
	return &ProtectResult{
		Manifest:      r.Manifest,
		BundlePath:    r.BundlePath,
		GeneratedKey:  r.GeneratedKey,
		Shares:        r.Shares,
		SignatureAlgo: r.SignatureAlgo,
		Signature:     r.Signature,
	}
}

func toVpackopDecrypt(d DecryptOptions) vpackop.DecryptParams {
	return vpackop.DecryptParams{
		InputPath:       d.InputPath,
		InputBytes:      d.InputBytes,
		OutputPath:      d.OutputPath,
		OutputWriter:    d.OutputWriter,
		Key:             d.Key,
		Password:        d.Password,
		PrivateKey:      d.PrivateKey,
		PrivateKeyPath:  d.PrivateKeyPath,
		KMSProvider:     d.KMSProvider,
		AAD:             d.AAD,
		ParallelWorkers: d.ParallelWorkers,
		KMSUnwrap:       d.KMSUnwrap,
	}
}
