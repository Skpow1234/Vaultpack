package vpackop

import (
	"fmt"
	"os"
)

// pemPath returns a filesystem path for PEM material, writing a temp file when
// only in-memory bytes are supplied. The cleanup func removes the temp file.
func pemPath(data []byte, path, prefix string) (string, func(), error) {
	if path != "" {
		return path, func() {}, nil
	}
	if len(data) == 0 {
		return "", nil, fmt.Errorf("pem: path or PEM bytes required")
	}
	f, err := os.CreateTemp("", prefix+"-*.pem")
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, err
	}
	name := f.Name()
	return name, func() { os.Remove(name) }, nil
}
