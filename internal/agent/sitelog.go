package agent

import (
	"bytes"
	"errors"
	"io"
	"io/fs"

	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Limits of the log viewers (USR-STAT-03, ADR-0012).
const (
	LogMaxLines    = 1000
	LogMaxContains = 200
	LogMaxChunk    = 1 << 20
	logScanMax     = 64 << 20 // how far back a tail looks for matching lines
	logBlock       = 64 << 10
)

// Log kinds.
const (
	LogAccess = "access"
	LogError  = "error"
)

func (w *Web) logFile(username, kind string) (*fsx.Root, string, error) {
	if validate.Username(username) != nil {
		return nil, "", invalid("%q is not an account name", username)
	}
	if kind != LogAccess && kind != LogError {
		return nil, "", invalid("log %q: want access or error", kind)
	}
	u, err := lookup(username)
	if err != nil {
		return nil, "", err
	}
	if u == nil || u.Name != AccountMarker {
		return nil, "", ErrNotOurUser
	}
	root, err := fsx.OpenRoot(w.LogDir)
	if err != nil {
		return nil, "", err
	}
	return root, username + "." + kind + ".log", nil
}

// TailLog returns the last lines of an account's access or error log, oldest
// first; with contains, only lines holding that text. A missing log is empty.
func (w *Web) TailLog(username, kind string, lines int, contains string) ([]string, error) {
	if lines < 1 || lines > LogMaxLines {
		return nil, invalid("lines: 1 to %d", LogMaxLines)
	}
	if len(contains) > LogMaxContains || bytes.ContainsAny([]byte(contains), "\r\n") {
		return nil, invalid("the search text is one line of at most %d bytes", LogMaxContains)
	}
	root, name, err := w.logFile(username, kind)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return tailLines(f, fi.Size(), lines, contains)
}

// tailLines returns the last lines of r (size bytes) holding contains, oldest first.
func tailLines(r io.ReaderAt, end int64, lines int, contains string) ([]string, error) {
	var found [][]byte // newest first
	var carry []byte   // the start of a line that began in the block before
	for pos := end; pos > 0 && end-pos < logScanMax && len(found) < lines; {
		n := min(int64(logBlock), pos)
		pos -= n
		buf := make([]byte, n, int(n)+len(carry))
		if _, err := r.ReadAt(buf, pos); err != nil {
			return nil, err
		}
		buf = append(buf, carry...)
		parts := bytes.Split(buf, []byte("\n"))
		carry = parts[0] // may continue further back
		for i := len(parts) - 1; i >= 1 && len(found) < lines; i-- {
			if len(parts[i]) > 0 && bytes.Contains(parts[i], []byte(contains)) {
				found = append(found, parts[i])
			}
		}
		if pos == 0 && len(carry) > 0 && len(found) < lines && bytes.Contains(carry, []byte(contains)) {
			found = append(found, carry)
		}
	}
	out := make([]string, len(found))
	for i, l := range found {
		out[len(found)-1-i] = string(l)
	}
	return out, nil
}

// ReadLog returns up to length bytes of an account's log from offset, and
// the log's size, for downloading it in parts.
func (w *Web) ReadLog(username, kind string, offset, length int64) ([]byte, int64, error) {
	if offset < 0 || length < 1 || length > LogMaxChunk {
		return nil, 0, invalid("offset and length: a part of at most %d bytes", LogMaxChunk)
	}
	root, name, err := w.logFile(username, kind)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, min(length, max(fi.Size()-offset, 0)))
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	return buf[:n], fi.Size(), nil
}
