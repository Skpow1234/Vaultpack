package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/Skpow1234/Vaultpack/internal/bundle"
)

// hashBundleFile returns the lowercase-hex SHA-256 of the .vpack file at path.
// Used to record the previous bundle's identity in rotation history.
func hashBundleFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hash bundle: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// appendRotation prepares the manifest for a rotation operation:
//   - clears the old signature (the new manifest invalidates it),
//   - appends a RotationEntry that records the previous bundle hash and the op,
//   - updates CreatedAt to the rotation timestamp.
//
// The caller is responsible for writing the modified manifest back to a bundle.
func appendRotation(m *bundle.Manifest, prevBundleHash, operation, notes string) {
	m.SignatureAlgo = nil
	m.SignedAt = nil
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	m.RotatedFrom = append(m.RotatedFrom, bundle.RotationEntry{
		Operation:  operation,
		RotatedAt:  m.CreatedAt,
		BundleHash: prevBundleHash,
		Notes:      notes,
	})
}
