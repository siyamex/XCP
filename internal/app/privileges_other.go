//go:build !linux

package app

// DropPrivileges is a no-op outside Linux (development machines).
func DropPrivileges(string) error { return nil }
