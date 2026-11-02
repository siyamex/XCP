//go:build !unix

package logd

import "io/fs"

// inode is not known here: rotation then shows only as a file that shrank.
// xcp-logd runs on Linux; this is for building and testing elsewhere.
func inode(fs.FileInfo) uint64 { return 1 }
