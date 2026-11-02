package agent

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRepackHome(t *testing.T) {
	var in bytes.Buffer
	tw := tar.NewWriter(&in)
	for _, h := range []*tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o711},
		{Name: "./public_html/", Typeflag: tar.TypeDir, Mode: 0o750},
		{Name: "./public_html/index.php", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5, Uid: 10001},
		{Name: "./link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	tw.Close()

	var out bytes.Buffer
	ht := &hashingTar{tw: tar.NewWriter(&out), sums: map[string]string{}}
	if err := repackHome(ht, &in); err != nil {
		t.Fatal(err)
	}
	ht.tw.Close()
	tr := tar.NewReader(&out)
	var names []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Name == "homedir/link" && (h.Typeflag != tar.TypeSymlink || h.Linkname != "/etc/passwd") {
			t.Errorf("the symlink is kept as a link, not followed: %+v", h)
		}
		if h.Name == "homedir/public_html/index.php" && h.Uid != 10001 {
			t.Errorf("owner lost: %+v", h)
		}
	}
	want := []string{"homedir/", "homedir/public_html", "homedir/public_html/index.php", "homedir/link", "homedir/escape"}
	if len(names) != len(want) {
		t.Fatalf("entries %q, want %q", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("entry %d: %q, want %q (nothing may leave homedir/)", i, names[i], want[i])
		}
	}
	x5 := sha256.Sum256([]byte("xxxxx"))
	if ht.sums["homedir/public_html/index.php"] != hex.EncodeToString(x5[:]) || len(ht.sums) != 2 {
		t.Errorf("checksums %v", ht.sums)
	}
}

func TestBackupFilesAreTheAccounts(t *testing.T) {
	for _, c := range []struct {
		user, file string
		ok         bool
	}{
		{"alice", "alice-20261102T101500Z.tar.zst", true},
		{"alice", "bob-20261102T101500Z.tar.zst", false},
		{"alice", "../alice-20261102T101500Z.tar.zst", false},
		{"alice", "alice-20261102T101500Z.tar.zst.part", false},
		{"alice", ".staging", false},
	} {
		if err := CheckBackupFile(c.user, c.file); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.user, c.file, err)
		}
	}
	b := &Backups{Dir: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(b.Dir, "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := "alice-20261102T101500Z.tar.zst"
	if err := os.WriteFile(filepath.Join(b.Dir, "alice", name), bytes.Repeat([]byte("b"), 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	data, size, err := b.Read("alice", name, 2<<20, BackupMaxRead)
	if err != nil || size != 3<<20 || len(data) != BackupMaxRead {
		t.Fatalf("read a part: %d of %d, %v", len(data), size, err)
	}
	if data, _, _ = b.Read("alice", name, 3<<20, BackupMaxRead); len(data) != 0 {
		t.Fatalf("read past the end: %d bytes", len(data))
	}
	if _, _, err := b.Read("bob", name, 0, 10); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("bob reads alice's backup: %v", err)
	}
	if ok, err := b.Delete("alice", name); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, _ := b.Delete("alice", name); ok {
		t.Error("deleted twice")
	}
	if ok, err := b.RemoveAccount("alice"); !ok || err != nil {
		t.Fatalf("remove the account's folder: %v %v", ok, err)
	}
}
