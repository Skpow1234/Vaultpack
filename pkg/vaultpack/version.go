package vaultpack

// Version is the SDK's semver. Bumped on every release.
//
// The version reported here is the SDK API version, not the CLI's build
// version (which is set at link time via -ldflags). The two move
// independently — adding a CLI flag does not require an SDK bump if no
// exported identifier is touched.
const Version = "0.1.0"
