// Package version holds build information set at link time.
package version

// Version is overridden with -ldflags "-X .../internal/version.Version=v1.2.3".
var Version = "dev"
