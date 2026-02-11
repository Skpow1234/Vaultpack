package util

import (
	"bytes"
	"testing"
)

func TestB64RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"binary", []byte{0x00, 0xFF, 0x80, 0x7F}},
		{"32 bytes key", bytes.Repeat([]byte{0xAB}, 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := B64Encode(tt.input)
			decoded, err := B64Decode(encoded)
			if err != nil {
				t.Fatalf("B64Decode error: %v", err)
			}
			if !bytes.Equal(decoded, tt.input) {
				t.Errorf("roundtrip mismatch: got %v, want %v", decoded, tt.input)
			}
		})
	}
}

func TestB64Decode_Invalid(t *testing.T) {
	_, err := B64Decode("not!valid!base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}
