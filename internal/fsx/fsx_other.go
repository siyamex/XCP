//go:build !linux

package fsx

// DEVELOPMENT FALLBACK ONLY. Production runs on Linux (fsx_linux.go).
// os.Root keeps lookups inside the root, but unlike the Linux version it
// follows symlinks that stay inside the root, and the symlink and
// no-replace checks below are not race-free.

import (
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

type sysRoot struct {
	root *os.Root
}

func openSysRoot(dir string) (sysRoot, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return sysRoot{}, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return sysRoot{}, ErrSymlink
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return sysRoot{}, err
	}
	return sysRoot{root: r}, nil
}

func (s sysRoot) close() error { return s.root.Close() }

func (s sysRoot) noSymlink(rel string) error {
	fi, err := s.root.Lstat(rel)
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return ErrSymlink
	}
	return nil
}

func (s sysRoot) openFile(rel string, flag int, perm fs.FileMode) (*os.File, error) {
	if err := s.noSymlink(rel); err != nil {
		return nil, err
	}
	return s.root.OpenFile(rel, flag, perm)
}

func (s sysRoot) lstat(rel string) (fs.FileInfo, error) { return s.root.Lstat(rel) }

func (s sysRoot) readDir(rel string) ([]fs.DirEntry, error) {
	f, err := s.openFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return ents, nil
}

func (s sysRoot) mkdir(rel string, perm fs.FileMode) error { return s.root.Mkdir(rel, perm) }

func (s sysRoot) remove(rel string) error { return s.root.Remove(rel) }

func (s sysRoot) rename(from, to string) error {
	if _, err := s.root.Lstat(to); err == nil {
		return fs.ErrExist
	}
	return s.root.Rename(from, to)
}

func (s sysRoot) chmod(rel string, mode fs.FileMode) error {
	if err := s.noSymlink(rel); err != nil {
		return err
	}
	return s.root.Chmod(rel, mode)
}

func (s sysRoot) chown(rel string, uid, gid int) error { return s.root.Lchown(rel, uid, gid) }

func (s sysRoot) writeFileAtomic(rel string, data []byte, perm fs.FileMode) (err error) {
	if err := s.noSymlink(rel); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(rel), ".xcp-tmp-"+hex.EncodeToString(rnd[:]))
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			_ = s.root.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return s.root.Rename(tmp, rel)
}
