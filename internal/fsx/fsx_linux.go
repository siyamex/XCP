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
	how := unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: resolveFlags}
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
		if err != unix.EAGAIN && err != unix.EINTR {
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
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return ents, nil
}

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
	if err == unix.EISDIR {
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
		return errors.New("fsx: openat2 not supported (Linux 5.6+ required)")
	}
	return err // unix.Errno already matches fs.ErrNotExist, fs.ErrExist, fs.ErrPermission
}
