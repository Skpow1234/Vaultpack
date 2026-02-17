package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Registry maps scheme/algo names to the plugin executable path.
type Registry struct {
	mu       sync.RWMutex
	kemPath  map[string]string // scheme -> path
	signPath map[string]string // algo -> path
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		kemPath:  make(map[string]string),
		signPath: make(map[string]string),
	}
}

// KEMScheme returns the plugin path for the given KEM scheme, or empty if built-in or unknown.
func (r *Registry) KEMScheme(scheme string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.kemPath[scheme]
}

// SignAlgo returns the plugin path for the given sign algorithm, or empty if built-in or unknown.
func (r *Registry) SignAlgo(algo string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.signPath[algo]
}

// KEMSchemes returns all plugin-registered KEM scheme names.
func (r *Registry) KEMSchemes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.kemPath))
	for n := range r.kemPath {
		names = append(names, n)
	}
	return names
}

// SignAlgos returns all plugin-registered sign algorithm names.
func (r *Registry) SignAlgos() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.signPath))
	for n := range r.signPath {
		names = append(names, n)
	}
	return names
}

// Discover scans dir for executables and registers capabilities from each (--vpack-list).
// Only registers names that are not already set (first plugin wins per name).
func (r *Registry) Discover(dir string) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read plugin dir: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip non-executables by extension on Windows
		if runtime.GOOS == "windows" && strings.ToLower(filepath.Ext(name)) != ".exe" {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
			continue
		}
		caps, err := listCapabilities(path)
		if err != nil {
			continue // skip broken plugins
		}
		r.mu.Lock()
		for _, s := range caps.KEM {
			if _, ok := r.kemPath[s]; !ok {
				r.kemPath[s] = path
			}
		}
		for _, s := range caps.Sign {
			if _, ok := r.signPath[s]; !ok {
				r.signPath[s] = path
			}
		}
		r.mu.Unlock()
	}
	return nil
}

func listCapabilities(pluginPath string) (*Capabilities, error) {
	cmd := exec.Command(pluginPath, "--vpack-list")
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var caps Capabilities
	if err := json.Unmarshal(bytesTrim(out), &caps); err != nil {
		return nil, err
	}
	return &caps, nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
