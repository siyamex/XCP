//go:build linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// attackSetup builds:
//
//	outside/secret.txt                 (must never be readable or writable)
//	root/link-out    -> ../outside     (symlink escaping the root)
//	root/link-abs    -> /etc           (absolute symlink)
//	root/link-file   -> ../outside/secret.txt
//	root/inner-link  -> real           (symlink staying inside the root)
//	root/real/file.txt
func attackSetup(t *testing.T) (*Root, string) {
	t.Helper()
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	must(t, os.MkdirAll(outside, 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "real"), 0o755))
	must(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "real", "file.txt"), []byte("ok"), 0o644))
	must(t, os.Symlink("../outside", filepath.Join(root, "link-out")))
	must(t, os.Symlink("/etc", filepath.Join(root, "link-abs")))
	must(t, os.Symlink("../outside/secret.txt", filepath.Join(root, "link-file")))
	must(t, os.Symlink("real", filepath.Join(root, "inner-link")))
	r, err := OpenRoot(root)
	must(t, err)
	t.Cleanup(func() { r.Close() })
	return r, outside
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	r, outside := attackSetup(t)

	reads := []string{"link-file", "link-out/secret.txt", "link-abs/passwd", "inner-link/file.txt"}
	for _, p := range reads {
		if _, err := r.ReadFile(p, 1024); !errors.Is(err, ErrSymlink) {
			t.Errorf("ReadFile(%q): err = %v, want ErrSymlink", p, err)
		}
	}
	if _, err := r.ReadDir("link-out"); !errors.Is(err, ErrSymlink) {
		t.Errorf("ReadDir through symlink: err = %v", err)
	}
	if err := r.WriteFileAtomic("link-out/new.txt", []byte("x"), 0o644); !errors.Is(err, ErrSymlink) {
		t.Errorf("write through symlinked dir: err = %v", err)
	}
	if err := r.Mkdir("link-out/dir", 0o755); !errors.Is(err, ErrSymlink) {
		t.Errorf("mkdir through symlinked dir: err = %v", err)
	}
	if err := r.MkdirAll("link-out/a/b", 0o755); !errors.Is(err, ErrSymlink) {
		t.Errorf("MkdirAll through symlink: err = %v", err)
	}
	if err := r.Chmod("link-file", 0o777); !errors.Is(err, ErrSymlink) {
		t.Errorf("chmod symlink: err = %v", err)
	}
	if err := r.Rename("link-out/secret.txt", "stolen.txt"); !errors.Is(err, ErrSymlink) {
		t.Errorf("rename out through symlink: err = %v", err)
	}

	// Nothing outside changed.
	b, _ := os.ReadFile(filepath.Join(outside, "secret.txt"))
	fi, _ := os.Stat(filepath.Join(outside, "secret.txt"))
	if string(b) != "secret" || fi.Mode().Perm() != 0o644 {
		t.Fatal("file outside the root was modified")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("files were created outside the root: %v", ents)
	}
}

func TestSymlinkItselfCanBeInspectedAndRemoved(t *testing.T) {
	r, outside := attackSetup(t)
	fi, err := r.Lstat("link-out")
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(link-out) = %v, %v; want symlink info", fi, err)
	}
	if err := r.WriteFileAtomic("link-file", []byte("replaced"), 0o644); err != nil {
		t.Fatalf("atomic write must replace the link entry itself: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "secret.txt")); string(b) != "secret" {
		t.Fatal("atomic write went through the symlink")
	}
	if err := r.Remove("link-out"); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("removing the symlink removed its target")
	}
}

func TestRootItselfMustNotBeSymlink(t *testing.T) {
	base := t.TempDir()
	must(t, os.Mkdir(filepath.Join(base, "real"), 0o755))
	must(t, os.Symlink("real", filepath.Join(base, "home")))
	if _, err := OpenRoot(filepath.Join(base, "home")); err == nil {
		t.Fatal("OpenRoot accepted a symlinked root")
	}
}

func TestRootRefusesWritingHardlinkedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("hard-link guard only applies when running as root")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	must(t, os.Mkdir(root, 0o755))
	target := filepath.Join(base, "target")
	must(t, os.WriteFile(target, []byte("x"), 0o644))
	must(t, os.Link(target, filepath.Join(root, "hl")))
	r, err := OpenRoot(root)
	must(t, err)
	defer r.Close()
	if _, err := r.OpenFile("hl", os.O_WRONLY, 0); !errors.Is(err, ErrHardlink) {
		t.Fatalf("err = %v, want ErrHardlink", err)
	}
}
