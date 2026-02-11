package util

import (
	"fmt"
	"testing"
)

func TestExitCodeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, ExitSuccess},
		{"verify failed", ErrVerifyFailed, ExitVerifyFailed},
		{"decrypt failed", ErrDecryptFailed, ExitDecryptFailed},
		{"key mismatch", ErrKeyMismatch, ExitDecryptFailed},
		{"bundle corrupted", ErrBundleCorrupted, ExitDecryptFailed},
		{"unsupported version", ErrUnsupportedVersion, ExitUnsupportedVersion},
		{"unsupported algorithm", ErrUnsupportedAlgorithm, ExitUnsupportedVersion},
		{"wrapped verify", fmt.Errorf("context: %w", ErrVerifyFailed), ExitVerifyFailed},
		{"generic", fmt.Errorf("something went wrong"), ExitGenericError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExitCodeForError(tt.err)
			if got != tt.want {
				t.Errorf("ExitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
