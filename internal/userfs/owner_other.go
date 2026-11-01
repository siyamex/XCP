//go:build !linux

package userfs

import "io/fs"

// owner is not known outside Linux (development only).
func owner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
