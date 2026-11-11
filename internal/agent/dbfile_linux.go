package agent

import (
	"io/fs"
	"syscall"
)

// fileUID returns the owner of an open file's info.
func fileUID(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
