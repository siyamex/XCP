//go:build linux

package agent

import (
	"github.com/siyamex/XCP/internal/execx"
	"golang.org/x/sys/unix"
)

func execxCmd(path string, args ...string) execx.Cmd {
	return execx.Cmd{Path: path, Args: args, MaxOutput: 1 << 20}
}

// statDisk reads a file system's size and inode counts.
func statDisk(m mount) (HostDisk, bool) {
	var s unix.Statfs_t
	if err := unix.Statfs(m.Mount, &s); err != nil || s.Blocks == 0 {
		return HostDisk{}, false
	}
	bs := uint64(s.Bsize) //nolint:gosec // G115: a block size
	return HostDisk{
		Mount: m.Mount, Device: m.Device, FS: m.FS, Total: s.Blocks * bs, Used: (s.Blocks - s.Bfree) * bs,
		Files: s.Files, FilesUsed: s.Files - s.Ffree,
	}, true
}
