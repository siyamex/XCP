//go:build linux

package fsx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// openat2 returns EAGAIN when a concurrent rename races the lookup; retry a few times.
const maxRetries = 16

type sysRoot struct{ fd int }

func openSysRoot(dir string) (sysRoot, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sysRoot{}, mapErr(err)
	}
	return sysRoot{fd: fd}, nil
}

func (s sysRoot) close() error { return unix.Close(s.fd) }

// open resolves rel strictly beneath the root.
func (s sysRoot) open(rel string, flags int, perm fs.FileMode) (int, error) {
	how := unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: resolveFlags} //nolint:gosec // G115: open flags are non-negative
	if flags&(unix.O_CREAT|unix.O_TMPFILE) != 0 {
		how.Mode = uint64(perm.Perm())
	}
	var err error
	for range maxRetries {
		var fd int
		fd, err = unix.Openat2(s.fd, rel, &how)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			break
		}
	}
	return -1, mapErr(err)
}

// parent opens the directory containing rel and returns it with rel's base name.
func (s sysRoot) parent(rel string, flags int) (int, string, error) {
	fd, err := s.open(path.Dir(rel), flags|unix.O_DIRECTORY, 0)
	return fd, path.Base(rel), err
}

func (s sysRoot) openFile(rel string, flag int, perm fs.FileMode) (*os.File, error) {
	fd, err := s.open(rel, flag|unix.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	// As root, writing into a user-controlled hard link could modify a file
	// elsewhere (e.g. one linked before fs.protected_hardlinks was enabled).
	if os.Geteuid() == 0 && flag&(os.O_WRONLY|os.O_RDWR) != 0 {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			f.Close()
			return nil, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink > 1 {
			f.Close()
			return nil, ErrHardlink
		}
	}
	return f, nil
}

func (s sysRoot) lstat(rel string) (fs.FileInfo, error) {
	// With O_PATH|O_NOFOLLOW a trailing symlink yields an fd for the link itself.
	fd, err := s.open(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()
	return f.Stat()
}

func (s sysRoot) readDir(rel string) ([]fs.DirEntry, error) {
	fd, err := s.open(rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOTDIR) {
		// With O_DIRECTORY the kernel reports a trailing symlink as ENOTDIR,
		// not ELOOP; say what it really is.
		if fi, lerr := s.lstat(rel); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return nil, ErrSymlink
		}
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	// Not f.ReadDir: its entries' Info() would lstat rel/name relative to
	// the process's working directory, not to this directory. Each entry
	// is stat'ed here against the directory fd itself.
	ents := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed meanwhile
			}
			return nil, err
		}
		ents = append(ents, dirEntry{info: statInfo{name: name, st: st}})
	}
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return ents, nil
}

// statInfo is an fs.FileInfo from a stat result; Sys is the *unix.Stat_t.
type statInfo struct {
	name string
	st   unix.Stat_t
}

func (i statInfo) Name() string       { return i.name }
func (i statInfo) Size() int64        { return i.st.Size }
func (i statInfo) ModTime() time.Time { return time.Unix(i.st.Mtim.Unix()) }
func (i statInfo) IsDir() bool        { return i.Mode().IsDir() }
func (i statInfo) Sys() any           { return &i.st }

// Mode converts the stat mode like the os package does.
func (i statInfo) Mode() fs.FileMode {
	m := fs.FileMode(i.st.Mode & 0o777)
	switch i.st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFIFO:
		m |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	case unix.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		m |= fs.ModeDevice
	}
	if i.st.Mode&unix.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if i.st.Mode&unix.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if i.st.Mode&unix.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// dirEntry is an fs.DirEntry with its info already read.
type dirEntry struct{ info statInfo }

func (d dirEntry) Name() string               { return d.info.name }
func (d dirEntry) IsDir() bool                { return d.info.IsDir() }
func (d dirEntry) Type() fs.FileMode          { return d.info.Mode().Type() }
func (d dirEntry) Info() (fs.FileInfo, error) { return d.info, nil }

func (s sysRoot) mkdir(rel string, perm fs.FileMode) error {
	dfd, base, err := s.parent(rel, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	return unix.Mkdirat(dfd, base, uint32(perm.Perm()))
}

func (s sysRoot) remove(rel string) error {
	dfd, base, err := s.parent(rel, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	err = unix.Unlinkat(dfd, base, 0)
	if errors.Is(err, unix.EISDIR) {
		err = unix.Unlinkat(dfd, base, unix.AT_REMOVEDIR)
	}
	return err
}

func (s sysRoot) rename(from, to string) error {
	ffd, fbase, err := s.parent(from, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(ffd)
	tfd, tbase, err := s.parent(to, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(tfd)
	return unix.Renameat2(ffd, fbase, tfd, tbase, unix.RENAME_NOREPLACE)
}

func (s sysRoot) chmod(rel string, mode fs.FileMode) error {
	fd, err := s.open(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	// fchmod does not accept O_PATH fds; chmod through the fd's /proc entry
	// targets exactly the inode we checked (same approach as glibc).
	return unix.Fchmodat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), uint32(mode.Perm()), 0)
}

func (s sysRoot) chown(rel string, uid, gid int) error {
	// O_PATH|O_NOFOLLOW gives an fd for the entry itself, even a symlink;
	// fchownat with AT_EMPTY_PATH then changes exactly that inode.
	fd, err := s.open(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH)
}

func (s sysRoot) writeFileAtomic(rel string, data []byte, perm fs.FileMode) (err error) {
	dfd, base, err := s.parent(rel, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".xcp-tmp-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		if err != nil {
			f.Close()
			_ = unix.Unlinkat(dfd, tmp, 0)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm.Perm()); err != nil { // undo umask
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(dfd, tmp, dfd, base); err != nil {
		return err
	}
	return unix.Fsync(dfd)
}

// mapErr turns resolution errors into package errors and the rest into fs errors.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ELOOP):
		return ErrSymlink
	case errors.Is(err, unix.EXDEV):
		return ErrEscape
	case errors.Is(err, unix.ENOSYS):
		return errors.New("fsx: openat2 is unavailable: kernel older than 5.6, or blocked by a seccomp filter " +
			"(systemd's RestrictSUIDSGID= does this)")
	}
	return err // unix.Errno already matches fs.ErrNotExist, fs.ErrExist, fs.ErrPermission
}
