//go:build unix

package logd

import (
	"io/fs"
	"syscall"
)

func inode(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
