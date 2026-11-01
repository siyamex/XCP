// Package userfs is the file manager's work on one account's files
// (USR-FILE-01..03, 05; ADR-0009). It runs inside xcp-userd as the account
// user, with every path relative to the home folder and resolved by fsx,
// so nothing here can leave the home, not even through the user's links.
package userfs

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/fsx"
)

// Limits of one operation.
const (
	MaxTextFile    = 2 << 20 // what the editor opens
	MaxSearchHits  = 500
	MaxWalkEntries = 200_000 // entries one search, usage scan or copy visits
	TrashDir       = ".trash"
)

// Errors the HTTP layer maps to status codes.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInvalid  = errors.New("invalid request")
	ErrTooLarge = errors.New("too large")
	ErrTooMany  = errors.New("too many files")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// FS is one account's home folder.
type FS struct {
	root  *fsx.Root
	Now   func() time.Time
	names sync.Map // uid/gid -> name
}

// Open opens the home folder dir.
func Open(dir string) (*FS, error) {
	r, err := fsx.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &FS{root: r, Now: time.Now}, nil
}

// Close releases the home folder.
func (f *FS) Close() error { return f.root.Close() }

// clean checks a path relative to the home folder; "" and "/" are the home.
func clean(p string) (string, error) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "/")
	if p == "" {
		return ".", nil
	}
	c, err := fsx.CleanRel(p)
	if err != nil {
		return "", invalid("%q is not a path in your home folder", p)
	}
	return c, nil
}

func cleanNonRoot(p string) (string, error) {
	c, err := clean(p)
	if err == nil && c == "." {
		return "", invalid("not possible on your home folder itself")
	}
	return c, err
}

// mapErr turns system errors into the package's.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%w: %w", ErrExists, err)
	case errors.Is(err, fsx.ErrSymlink):
		return invalid("the path goes through a symbolic link, which the file manager does not follow")
	case errors.Is(err, fsx.ErrInvalidPath), errors.Is(err, fsx.ErrEscape), errors.Is(err, fsx.ErrRootOp):
		return invalid("%v", err)
	}
	return err
}

// Entry is a file or folder.
type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Type    string    `json:"type"` // file, dir, link, other
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"` // "0644"
	ModTime time.Time `json:"mod_time"`
	Owner   string    `json:"owner"`
	Group   string    `json:"group"`
}

func (f *FS) name(id uint32, group bool) string {
	key := "u" + strconv.FormatUint(uint64(id), 10)
	if group {
		key = "g" + key[1:]
	}
	if v, ok := f.names.Load(key); ok {
		return v.(string)
	}
	n := strconv.FormatUint(uint64(id), 10)
	if group {
		if g, err := user.LookupGroupId(n); err == nil {
			n = g.Name
		}
	} else if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	f.names.Store(key, n)
	return n
}

func (f *FS) entry(p string, fi fs.FileInfo) Entry {
	e := Entry{Name: fi.Name(), Path: p, Size: fi.Size(), Mode: fmt.Sprintf("%04o", fi.Mode().Perm()), ModTime: fi.ModTime().UTC()}
	switch {
	case fi.Mode().IsDir():
		e.Type, e.Size = "dir", 0
	case fi.Mode()&fs.ModeSymlink != 0:
		e.Type = "link"
	case fi.Mode().IsRegular():
		e.Type = "file"
	default:
		e.Type = "other"
	}
	if uid, gid, ok := owner(fi); ok {
		e.Owner, e.Group = f.name(uid, false), f.name(gid, true)
	}
	return e
}

// Stat describes one path.
func (f *FS) Stat(p string) (Entry, error) {
	c, err := clean(p)
	if err != nil {
		return Entry{}, err
	}
	fi, err := f.root.Lstat(c)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	e := f.entry(c, fi)
	if c == "." {
		e.Name, e.Path = "", ""
	}
	return e, nil
}

// List lists a folder, folders first.
func (f *FS) List(p string) ([]Entry, error) {
	c, err := clean(p)
	if err != nil {
		return nil, err
	}
	ents, err := f.root.ReadDir(c)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Entry, 0, len(ents))
	for _, d := range ents {
		fi, err := d.Info()
		if err != nil {
			continue // gone meanwhile
		}
		out = append(out, f.entry(join(c, d.Name()), fi))
	}
	slices.SortStableFunc(out, func(a, b Entry) int {
		if (a.Type == "dir") != (b.Type == "dir") {
			if a.Type == "dir" {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

func join(dir, name string) string {
	if dir == "." {
		return name
	}
	return path.Join(dir, name)
}

// OpenRead opens a file for download.
func (f *FS) OpenRead(p string) (*os.File, Entry, error) {
	c, err := cleanNonRoot(p)
	if err != nil {
		return nil, Entry{}, err
	}
	fi, err := f.root.Lstat(c)
	if err != nil {
		return nil, Entry{}, mapErr(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, Entry{}, invalid("%s is not a file", c)
	}
	file, err := f.root.Open(c)
	if err != nil {
		return nil, Entry{}, mapErr(err)
	}
	return file, f.entry(c, fi), nil
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return hex.EncodeToString(b)
}

// Write stores r at p through a temporary file, so a broken upload never
// leaves half a file. maxBytes < 0 means no limit of its own (the disk
// quota still counts).
func (f *FS) Write(p string, r io.Reader, overwrite bool, maxBytes int64) (Entry, error) {
	c, err := cleanNonRoot(p)
	if err != nil {
		return Entry{}, err
	}
	mode := fs.FileMode(0o644)
	if fi, err := f.root.Lstat(c); err == nil {
		if !overwrite {
			return Entry{}, fmt.Errorf("%w: %s", ErrExists, c)
		}
		if !fi.Mode().IsRegular() {
			return Entry{}, invalid("%s is not a file", c)
		}
		mode = fi.Mode().Perm()
	}
	if dir := path.Dir(c); dir != "." {
		// Uploads of whole folders bring their subfolders.
		if err := f.root.MkdirAll(dir, 0o755); err != nil {
			return Entry{}, mapErr(err)
		}
	}
	tmp := join(path.Dir(c), "."+path.Base(c)+".xcp-upload-"+randomSuffix())
	file, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	src := r
	if maxBytes >= 0 {
		src = io.LimitReader(r, maxBytes+1)
	}
	n, err := io.Copy(file, src)
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err == nil && maxBytes >= 0 && n > maxBytes {
		err = fmt.Errorf("%w: more than %d bytes", ErrTooLarge, maxBytes)
	}
	if err == nil {
		err = f.root.Chmod(tmp, mode)
	}
	if err == nil {
		if _, serr := f.root.Lstat(c); serr == nil {
			err = f.root.Remove(c)
		}
	}
	if err == nil {
		err = f.root.Rename(tmp, c)
	}
	if err != nil {
		_ = f.root.Remove(tmp)
		return Entry{}, mapErr(err)
	}
	return f.Stat(c)
}

// Mkdir creates a folder (and missing parents).
func (f *FS) Mkdir(p string) (Entry, error) {
	c, err := cleanNonRoot(p)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.root.Lstat(c); err == nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrExists, c)
	}
	if err := f.root.MkdirAll(c, 0o755); err != nil {
		return Entry{}, mapErr(err)
	}
	return f.Stat(c)
}

// Rename moves or renames; it never replaces what is there.
func (f *FS) Rename(from, to string) (Entry, error) {
	a, err := cleanNonRoot(from)
	if err != nil {
		return Entry{}, err
	}
	b, err := cleanNonRoot(to)
	if err != nil {
		return Entry{}, err
	}
	if b == a || strings.HasPrefix(b, a+"/") {
		return Entry{}, invalid("a folder cannot move into itself")
	}
	if _, err := f.root.Lstat(b); err == nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrExists, b)
	}
	if err := f.root.Rename(a, b); err != nil {
		return Entry{}, mapErr(err)
	}
	return f.Stat(b)
}

// walk visits p and everything below it, folders before their content,
// without following links. It stops after MaxWalkEntries.
func (f *FS) walk(p string, fn func(p string, fi fs.FileInfo) error) error {
	seen := 0
	var visit func(p string, fi fs.FileInfo) error
	visit = func(p string, fi fs.FileInfo) error {
		if seen++; seen > MaxWalkEntries {
			return fmt.Errorf("%w: more than %d", ErrTooMany, MaxWalkEntries)
		}
		if err := fn(p, fi); err != nil {
			return err
		}
		if !fi.IsDir() {
			return nil
		}
		ents, err := f.root.ReadDir(p)
		if err != nil {
			return mapErr(err)
		}
		for _, d := range ents {
			cfi, err := d.Info()
			if err != nil {
				continue
			}
			if err := visit(join(p, d.Name()), cfi); err != nil {
				return err
			}
		}
		return nil
	}
	fi, err := f.root.Lstat(p)
	if err != nil {
		return mapErr(err)
	}
	return visit(p, fi)
}

// Copy copies a file or folder; links are skipped (they are not followed).
func (f *FS) Copy(from, to string) (Entry, error) {
	a, err := cleanNonRoot(from)
	if err != nil {
		return Entry{}, err
	}
	b, err := cleanNonRoot(to)
	if err != nil {
		return Entry{}, err
	}
	if b == a || strings.HasPrefix(b, a+"/") {
		return Entry{}, invalid("a folder cannot be copied into itself")
	}
	if _, err := f.root.Lstat(b); err == nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrExists, b)
	}
	err = f.walk(a, func(p string, fi fs.FileInfo) error {
		dst := b + strings.TrimPrefix(p, a)
		switch {
		case fi.IsDir():
			return mapErr(f.root.Mkdir(dst, fi.Mode().Perm()|0o700))
		case fi.Mode().IsRegular():
			return f.copyFile(p, dst, fi.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return f.Stat(b)
}

func (f *FS) copyFile(from, to string, mode fs.FileMode) error {
	src, err := f.root.Open(from)
	if err != nil {
		return mapErr(err)
	}
	defer src.Close()
	dst, err := f.root.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return mapErr(err)
	}
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	return err
}

// Trash moves paths into ~/.trash/<time>-<random>/, keeping their names.
// It returns that folder.
func (f *FS) Trash(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", invalid("nothing to delete")
	}
	var clean []string
	for _, p := range paths {
		c, err := cleanNonRoot(p)
		if err != nil {
			return "", err
		}
		if c == TrashDir || strings.HasPrefix(c, TrashDir+"/") {
			return "", invalid("files in the trash are deleted by emptying it")
		}
		clean = append(clean, c)
	}
	dir := TrashDir + "/" + f.Now().UTC().Format("20060102-150405") + "-" + randomSuffix()
	if err := f.root.MkdirAll(dir, 0o700); err != nil {
		return "", mapErr(err)
	}
	if err := f.root.Chmod(TrashDir, 0o700); err != nil {
		return "", mapErr(err)
	}
	for i, c := range clean {
		name := path.Base(c)
		if slices.ContainsFunc(clean[:i], func(o string) bool { return path.Base(o) == name }) {
			name += "." + strconv.Itoa(i)
		}
		if err := f.root.Rename(c, dir+"/"+name); err != nil {
			return dir, mapErr(err)
		}
	}
	return dir, nil
}

// Chmod sets permissions, optionally on everything below a folder too.
func (f *FS) Chmod(p string, mode fs.FileMode, recursive bool) error {
	c, err := cleanNonRoot(p)
	if err != nil {
		return err
	}
	if mode&^0o777 != 0 {
		return invalid("permissions are 000 to 777")
	}
	if !recursive {
		return mapErr(f.root.Chmod(c, mode))
	}
	return f.walk(c, func(p string, fi fs.FileInfo) error {
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		m := mode
		if fi.IsDir() {
			// Folders need x where files have r, or they cannot be opened.
			m |= (mode & 0o444) >> 2
		}
		return mapErr(f.root.Chmod(p, m))
	})
}

// Search finds names containing q (case-insensitively) below p.
func (f *FS) Search(p, q string) ([]Entry, bool, error) {
	c, err := clean(p)
	if err != nil {
		return nil, false, err
	}
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil, false, invalid("search for something")
	}
	var hits []Entry
	more := false
	err = f.walk(c, func(p string, fi fs.FileInfo) error {
		if p == TrashDir || strings.HasPrefix(p, TrashDir+"/") {
			return nil
		}
		if p != c && strings.Contains(strings.ToLower(fi.Name()), q) {
			if len(hits) == MaxSearchHits {
				more = true
				return errStop
			}
			hits = append(hits, f.entry(p, fi))
		}
		return nil
	})
	if errors.Is(err, errStop) || errors.Is(err, ErrTooMany) {
		return hits, true, nil
	}
	return hits, more, err
}

var errStop = errors.New("stop")

var fsxTooLarge = fsx.ErrTooLarge

// Usage is what takes space below a folder (USR-FILE-05).
type Usage struct {
	Path     string  `json:"path"`
	Total    int64   `json:"total"`
	Children []Entry `json:"children"` // folders with their whole size, largest first
	Largest  []Entry `json:"largest"`  // the largest files anywhere below
	Partial  bool    `json:"partial"`  // stopped at MaxWalkEntries
}

// DiskUsage measures a folder.
func (f *FS) DiskUsage(p string) (Usage, error) {
	c, err := clean(p)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{Path: c}
	top, err := f.List(c)
	if err != nil {
		return u, err
	}
	sizes := map[string]int64{}
	err = f.walk(c, func(p string, fi fs.FileInfo) error {
		if !fi.Mode().IsRegular() {
			return nil
		}
		u.Total += fi.Size()
		rest := strings.TrimPrefix(p, c+"/")
		if c == "." {
			rest = p
		}
		first, _, _ := strings.Cut(rest, "/")
		sizes[first] += fi.Size()
		e := f.entry(p, fi)
		i, _ := slices.BinarySearchFunc(u.Largest, e, func(a, b Entry) int { return cmp.Compare(b.Size, a.Size) })
		if i < 20 {
			u.Largest = slices.Insert(u.Largest, i, e)
			if len(u.Largest) > 20 {
				u.Largest = u.Largest[:20]
			}
		}
		return nil
	})
	if errors.Is(err, ErrTooMany) {
		u.Partial, err = true, nil
	}
	for _, e := range top {
		e.Size = sizes[e.Name]
		u.Children = append(u.Children, e)
	}
	slices.SortStableFunc(u.Children, func(a, b Entry) int { return cmp.Compare(b.Size, a.Size) })
	if u.Largest == nil {
		u.Largest = []Entry{}
	}
	return u, err
}
