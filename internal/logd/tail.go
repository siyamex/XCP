package logd

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
)

// Offset is how far a log file has been read: the file (by inode) and the
// byte after the last complete line read.
type Offset struct {
	Inode  uint64
	Offset int64
}

// MaxRead bounds what one ReadNew call returns from a file.
const MaxRead = 64 << 20

// ReadNew returns the complete lines added to path since off, and the
// offset to continue from. When the file was rotated (a new inode) the rest
// of the old one is read from path.1 first; a file that shrank was
// truncated and is read from the start. A file seen for the first time
// (off.Inode 0) is read from the start, or only from now on with fromEnd.
func ReadNew(path string, off Offset, fromEnd bool) ([]byte, Offset, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, off, nil
	}
	if err != nil {
		return nil, off, err
	}
	ino := inode(fi)
	var out []byte
	switch {
	case off.Inode == 0 && fromEnd:
		return nil, Offset{Inode: ino, Offset: fi.Size()}, nil
	case off.Inode == 0:
		off = Offset{Inode: ino}
	case ino != off.Inode:
		if old, err := os.Stat(path + ".1"); err == nil && inode(old) == off.Inode {
			// The old file ends here; a last line without a newline still counts.
			b, _, err := readFrom(path+".1", off.Offset, true)
			if err != nil {
				return nil, off, err
			}
			out = b
		}
		off = Offset{Inode: ino}
	case fi.Size() < off.Offset:
		off.Offset = 0
	}
	b, n, err := readFrom(path, off.Offset, false)
	if err != nil {
		return out, off, err
	}
	off.Offset += n
	return append(out, b...), off, nil
}

// readFrom reads from offset to the end (at most MaxRead), up to the last
// newline unless all is set. It returns the bytes it consumed.
func readFrom(path string, offset int64, all bool) ([]byte, int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: log files of this server's services
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxRead))
	if err != nil {
		return nil, 0, err
	}
	if !all {
		i := bytes.LastIndexByte(b, '\n')
		b = b[:i+1] // i = -1: nothing complete yet
	}
	return b, int64(len(b)), nil
}
