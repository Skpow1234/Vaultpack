package cli

import "os"

func writeFileHelper(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
