package plugin

var globalRegistry = NewRegistry()

// GlobalRegistry returns the process-wide plugin registry.
func GlobalRegistry() *Registry {
	return globalRegistry
}

// DiscoverFromDir runs discovery on pluginDir (env or config). Call from CLI when plugin dir is known.
func DiscoverFromDir(pluginDir string) {
	if pluginDir != "" {
		_ = globalRegistry.Discover(pluginDir)
	}
}
