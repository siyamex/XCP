//go:build !linux

package agent

import "io/fs"

// fileUID is not available off Linux; xcp-agent runs on Linux.
func fileUID(fs.FileInfo) (int, bool) { return 0, false }
