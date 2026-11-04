//go:build !linux

package agent

import "github.com/siyamex/XCP/internal/execx"

func execxCmd(path string, args ...string) execx.Cmd {
	return execx.Cmd{Path: path, Args: args, MaxOutput: 1 << 20}
}

// statDisk is not available off Linux; xcp-agent runs on Linux.
func statDisk(mount) (HostDisk, bool) { return HostDisk{}, false }
