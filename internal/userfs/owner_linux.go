package userfs

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// owner reads the uid and gid from a FileInfo: os.Lstat's (syscall) or
// fsx.ReadDir's entries (unix).
func owner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	switch st := fi.Sys().(type) {
	case *syscall.Stat_t:
		return st.Uid, st.Gid, true
	case *unix.Stat_t:
		return st.Uid, st.Gid, true
	}
	return 0, 0, false
}
