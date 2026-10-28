// Package fsx does file operations confined to one directory tree (a Root),
// usually an account's home. See 07-security.md §5.
//
// On Linux every path is resolved with openat2(RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS) relative to an fd for the
// root, so neither "..", absolute paths, nor symlinks (even ones swapped in
// during the call) can reach outside the root. Symlinks inside the root are
// never followed; they can be listed, stat'ed (Lstat), renamed and removed.
//
// Other platforms use a development-only fallback; production is Linux only.
package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Limits for relative paths.
const (
	MaxPathLen = 4096
	MaxNameLen = 255
)

var (
	// ErrInvalidPath means the relative path is malformed (absolute, "..", NUL, too long...).
	ErrInvalidPath = errors.New("fsx: invalid path")
	// ErrSymlink means a symlink was found where following it is not allowed.
	ErrSymlink = errors.New("fsx: symlink not allowed")
	// ErrEscape means resolution tried to leave the root.
	ErrEscape = errors.New("fsx: path escapes root")
	// ErrRootOp means the operation is not allowed on the root directory itself.
	ErrRootOp = errors.New("fsx: operation not allowed on root")
	// ErrHardlink means a write was refused through a file with several hard links while privileged.
	ErrHardlink = errors.New("fsx: refusing to write multiply-linked file as root")
	// ErrTooLarge means the ReadFile limit was exceeded.
	ErrTooLarge = errors.New("fsx: file too large")
)

// Root is an open directory that confines all operations below it.
// It is safe for concurrent use.
type Root struct {
	name string
	sys  sysRoot
}

// OpenRoot opens dir as a root. dir itself must not be a symlink.
func OpenRoot(dir string) (*Root, error) {
	sys, err := openSysRoot(dir)
	if err != nil {
		return nil, &fs.PathError{Op: "openroot", Path: dir, Err: err}
	}
	return &Root{name: dir, sys: sys}, nil
}

// Name returns the directory the root was opened with.
func (r *Root) Name() string { return r.name }

// Close releases the root.
func (r *Root) Close() error { return r.sys.close() }

// CleanRel validates a path relative to a root and returns it in clean,
// slash-separated form. "" and "." mean the root itself. Any ".." element is
// rejected, even when it would stay inside the root, so paths are never ambiguous.
func CleanRel(rel string) (string, error) {
	if rel == "" || rel == "." {
		return ".", nil
	}
	switch {
	case len(rel) > MaxPathLen:
		return "", fmt.Errorf("%w: longer than %d bytes", ErrInvalidPath, MaxPathLen)
	case strings.ContainsRune(rel, 0):
		return "", fmt.Errorf("%w: contains NUL", ErrInvalidPath)
	case strings.ContainsRune(rel, '\\'):
		return "", fmt.Errorf("%w: contains backslash", ErrInvalidPath)
	case strings.HasPrefix(rel, "/"):
		return "", fmt.Errorf("%w: absolute path", ErrInvalidPath)
	}
	for _, elem := range strings.Split(rel, "/") {
		if elem == ".." {
			return "", fmt.Errorf("%w: contains a \"..\" element", ErrInvalidPath)
		}
		if len(elem) > MaxNameLen {
			return "", fmt.Errorf("%w: name longer than %d bytes", ErrInvalidPath, MaxNameLen)
		}
	}
	return path.Clean(rel), nil
}

func cleanNonRoot(rel string) (string, error) {
	c, err := CleanRel(rel)
	if err != nil {
		return "", err
	}
	if c == "." {
		return "", ErrRootOp
	}
	return c, nil
}

func pathErr(op, rel string, err error) error {
	if err == nil {
		return nil
	}
	return &fs.PathError{Op: op, Path: rel, Err: err}
}

// OpenFile opens a file below the root. The final element must not be a symlink.
func (r *Root) OpenFile(rel string, flag int, perm fs.FileMode) (*os.File, error) {
	c, err := CleanRel(rel)
	if err != nil {
		return nil, pathErr("open", rel, err)
	}
	f, err := r.sys.openFile(c, flag, perm)
	return f, pathErr("open", c, err)
}

// Open opens a file for reading.
func (r *Root) Open(rel string) (*os.File, error) { return r.OpenFile(rel, os.O_RDONLY, 0) }

// ReadFile reads a whole file, failing with ErrTooLarge beyond limit bytes.
func (r *Root) ReadFile(rel string, limit int64) ([]byte, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, pathErr("read", rel, err)
	}
	if int64(len(b)) > limit {
		return nil, pathErr("read", rel, ErrTooLarge)
	}
	return b, nil
}

// Lstat returns file info without following a final symlink.
func (r *Root) Lstat(rel string) (fs.FileInfo, error) {
	c, err := CleanRel(rel)
	if err != nil {
		return nil, pathErr("lstat", rel, err)
	}
	fi, err := r.sys.lstat(c)
	return fi, pathErr("lstat", c, err)
}

// ReadDir lists a directory, sorted by name.
func (r *Root) ReadDir(rel string) ([]fs.DirEntry, error) {
	c, err := CleanRel(rel)
	if err != nil {
		return nil, pathErr("readdir", rel, err)
	}
	ents, err := r.sys.readDir(c)
	return ents, pathErr("readdir", c, err)
}

// Mkdir creates one directory.
func (r *Root) Mkdir(rel string, perm fs.FileMode) error {
	c, err := cleanNonRoot(rel)
	if err != nil {
		return pathErr("mkdir", rel, err)
	}
	return pathErr("mkdir", c, r.sys.mkdir(c, perm))
}

// MkdirAll creates a directory and any missing parents. Existing symlinks on
// the way are not followed (the call fails instead).
func (r *Root) MkdirAll(rel string, perm fs.FileMode) error {
	c, err := CleanRel(rel)
	if err != nil {
		return pathErr("mkdir", rel, err)
	}
	if c == "." {
		return nil
	}
	cur := ""
	for _, elem := range strings.Split(c, "/") {
		cur = path.Join(cur, elem)
		err := r.sys.mkdir(cur, perm)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return pathErr("mkdir", cur, err)
		}
		fi, serr := r.sys.lstat(cur)
		if serr != nil {
			return pathErr("mkdir", cur, serr)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return pathErr("mkdir", cur, ErrSymlink)
		}
		if !fi.IsDir() {
			return pathErr("mkdir", cur, fmt.Errorf("not a directory (mode %v)", fi.Mode().Type()))
		}
	}
	return nil
}

// Remove deletes a file, symlink, or empty directory.
func (r *Root) Remove(rel string) error {
	c, err := cleanNonRoot(rel)
	if err != nil {
		return pathErr("remove", rel, err)
	}
	return pathErr("remove", c, r.sys.remove(c))
}

// Rename moves from → to. It fails if to already exists.
func (r *Root) Rename(from, to string) error {
	cf, err := cleanNonRoot(from)
	if err != nil {
		return pathErr("rename", from, err)
	}
	ct, err := cleanNonRoot(to)
	if err != nil {
		return pathErr("rename", to, err)
	}
	return pathErr("rename", cf, r.sys.rename(cf, ct))
}

// Chmod sets permission bits (only 0o777; setuid/setgid/sticky are refused).
// It refuses symlinks.
func (r *Root) Chmod(rel string, mode fs.FileMode) error {
	c, err := cleanNonRoot(rel)
	if err != nil {
		return pathErr("chmod", rel, err)
	}
	if mode&^fs.ModePerm != 0 {
		return pathErr("chmod", c, fmt.Errorf("%w: only permission bits 0777 may be set", ErrInvalidPath))
	}
	return pathErr("chmod", c, r.sys.chmod(c, mode))
}

// WriteFileAtomic writes data to a temp file in the same directory, fsyncs it,
// and renames it over rel, so readers see the old or the new content, never half.
func (r *Root) WriteFileAtomic(rel string, data []byte, perm fs.FileMode) error {
	c, err := cleanNonRoot(rel)
	if err != nil {
		return pathErr("write", rel, err)
	}
	return pathErr("write", c, r.sys.writeFileAtomic(c, data, perm))
}
