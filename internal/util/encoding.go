package util

import "encoding/base64"

// B64Encode returns the standard base64 encoding of src.
func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// B64Decode decodes a standard base64 string.
func B64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
