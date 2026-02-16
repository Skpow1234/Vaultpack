package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	// EnvConfigPath is the environment variable for config file path.
	EnvConfigPath = "VPACK_CONFIG"
	// EnvProfile is the environment variable for profile name.
	EnvProfile = "VPACK_PROFILE"
)

// EffectiveConfig holds the merged configuration (defaults + config file + profile).
type EffectiveConfig struct {
	AuditLog        string   `mapstructure:"audit_log" json:"audit_log"`
	Cipher          string   `mapstructure:"cipher" json:"cipher"`
	ChunkSize       int      `mapstructure:"chunk_size" json:"chunk_size"`
	OutputDir       string   `mapstructure:"output_dir" json:"output_dir"`
	DefaultKeyPath  string   `mapstructure:"default_key_path" json:"default_key_path"`
	DefaultPubPath  string   `mapstructure:"default_pubkey_path" json:"default_pubkey_path"`
	Recipients      []string `mapstructure:"recipients" json:"recipients,omitempty"`
}

// Profile holds profile-specific overrides.
type Profile struct {
	AuditLog       string   `mapstructure:"audit_log"`
	Cipher         string   `mapstructure:"cipher"`
	ChunkSize      int      `mapstructure:"chunk_size"`
	OutputDir      string   `mapstructure:"output_dir"`
	DefaultKeyPath string   `mapstructure:"default_key_path"`
	DefaultPubPath string   `mapstructure:"default_pubkey_path"`
	Recipients     []string `mapstructure:"recipients"`
}

// ConfigFile represents the root config file structure (optional base + profiles).
type ConfigFile struct {
	AuditLog        string             `mapstructure:"audit_log"`
	Cipher          string             `mapstructure:"cipher"`
	ChunkSize       int                `mapstructure:"chunk_size"`
	OutputDir       string             `mapstructure:"output_dir"`
	DefaultKeyPath  string             `mapstructure:"default_key_path"`
	DefaultPubPath  string             `mapstructure:"default_pubkey_path"`
	Recipients      []string           `mapstructure:"recipients"`
	Profiles        map[string]Profile `mapstructure:"profiles"`
}

// DefaultEffective returns the built-in default effective config.
func DefaultEffective() EffectiveConfig {
	return EffectiveConfig{
		Cipher:    "aes-256-gcm",
		ChunkSize: 65536,
		OutputDir: ".",
	}
}

var (
	// loaded is the config loaded in the current process (set by Load).
	loaded *EffectiveConfig
)

// Load reads config from the given path (or discovers it), applies the given profile, and stores the result.
// Config path: if path is non-empty it is used; else VPACK_CONFIG; else ~/.vpack.yaml, ./.vpack.yaml (first found).
// Profile: if profile is non-empty it is used; else VPACK_PROFILE; else no profile.
// Precedence for final values: caller will layer CLI/env on top; this returns file-based effective config.
func Load(configPath, profile string) (*EffectiveConfig, error) {
	base := DefaultEffective()

	if configPath == "" {
		configPath = os.Getenv(EnvConfigPath)
	}
	if profile == "" {
		profile = os.Getenv(EnvProfile)
	}

	if configPath != "" {
		// Single explicit file.
		if err := readAndMerge(configPath, profile, &base); err != nil {
			return nil, err
		}
	} else {
		// Search default locations.
		home, _ := os.UserHomeDir()
		candidates := []string{}
		if home != "" {
			candidates = append(candidates, filepath.Join(home, ".vpack.yaml"), filepath.Join(home, ".vpack.yml"))
		}
		wd, _ := os.Getwd()
		if wd != "" {
			candidates = append(candidates, filepath.Join(wd, ".vpack.yaml"), filepath.Join(wd, ".vpack.yml"))
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				if err := readAndMerge(p, profile, &base); err != nil {
					return nil, err
				}
				break
			}
		}
	}

	loaded = &base
	return loaded, nil
}

// readAndMerge reads one config file and merges it (and optional profile) into base.
func readAndMerge(path, profile string, base *EffectiveConfig) error {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		// Config file optional: missing file is not an error (viper may return *fs.PathError when using SetConfigFile).
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) && errors.Is(pathErr.Err, fs.ErrNotExist) {
			return nil
		}
		if errors.As(err, new(viper.ConfigFileNotFoundError)) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}

	// Unmarshal base (root) keys.
	if v.IsSet("audit_log") {
		base.AuditLog = v.GetString("audit_log")
	}
	if v.IsSet("cipher") {
		base.Cipher = v.GetString("cipher")
	}
	if v.IsSet("chunk_size") {
		base.ChunkSize = v.GetInt("chunk_size")
	}
	if v.IsSet("output_dir") {
		base.OutputDir = v.GetString("output_dir")
	}
	if v.IsSet("default_key_path") {
		base.DefaultKeyPath = v.GetString("default_key_path")
	}
	if v.IsSet("default_pubkey_path") {
		base.DefaultPubPath = v.GetString("default_pubkey_path")
	}
	if v.IsSet("recipients") {
		base.Recipients = v.GetStringSlice("recipients")
	}

	// Apply profile overrides.
	if profile != "" && v.IsSet("profiles") {
		profiles := v.GetStringMap("profiles")
		if p, ok := profiles[profile].(map[string]interface{}); ok {
			if v, ok := p["audit_log"].(string); ok && v != "" {
				base.AuditLog = v
			}
			if v, ok := p["cipher"].(string); ok && v != "" {
				base.Cipher = v
			}
			if v, ok := p["chunk_size"].(int); ok && v > 0 {
				base.ChunkSize = v
			}
			if v, ok := p["output_dir"].(string); ok && v != "" {
				base.OutputDir = v
			}
			if v, ok := p["default_key_path"].(string); ok && v != "" {
				base.DefaultKeyPath = v
			}
			if v, ok := p["default_pubkey_path"].(string); ok && v != "" {
				base.DefaultPubPath = v
			}
			if r, ok := p["recipients"].([]interface{}); ok && len(r) > 0 {
				base.Recipients = make([]string, 0, len(r))
				for _, x := range r {
					if s, ok := x.(string); ok {
						base.Recipients = append(base.Recipients, s)
					}
				}
			}
		}
	}

	return nil
}

// Get returns the loaded effective config, or nil if Load was never called or failed.
func Get() *EffectiveConfig {
	return loaded
}

// SetLoaded sets the effective config (for tests).
func SetLoaded(c *EffectiveConfig) {
	loaded = c
}
