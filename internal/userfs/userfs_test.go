package userfs

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func newFS(t *testing.T) (*FS, string) {
	t.Helper()
	dir := t.TempDir()
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	f.Now = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	return f, dir
}

func write(t *testing.T, f *FS, p, content string) {
	t.Helper()
	if _, err := f.Write(p, strings.NewReader(content), true, -1); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func names(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name
	}
	return out
}

func TestBasicOperations(t *testing.T) {
	f, dir := newFS(t)
	if _, err := f.Mkdir("public_html/img"); err != nil {
		t.Fatal(err)
	}
	write(t, f, "public_html/index.php", "<?php echo 1;")
	write(t, f, "notes.txt", "hello")
	if _, err := f.Write("notes.txt", strings.NewReader("x"), false, -1); !errors.Is(err, ErrExists) {
		t.Errorf("write without overwrite: %v", err)
	}
	if _, err := f.Write("big.bin", strings.NewReader("12345"), false, 4); !errors.Is(err, ErrTooLarge) {
		t.Errorf("limit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "big.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a failed upload left a file")
	}
	ls, err := f.List("")
	if err != nil || !slices.Equal(names(ls), []string{"public_html", "notes.txt"}) {
		t.Fatalf("list: %v %v", names(ls), err)
	}
	for _, bad := range []string{"../etc/passwd", "/../../x", "a/../../b"} {
		if _, err := f.List(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := f.Rename("notes.txt", "public_html/notes.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Rename("public_html", "public_html/img/inside"); !errors.Is(err, ErrInvalid) {
		t.Errorf("move into itself: %v", err)
	}
	if _, err := f.Copy("public_html", "site-copy"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "site-copy", "notes.txt")); err != nil || string(b) != "hello" {
		t.Fatalf("copy: %q %v", b, err)
	}
	trash, err := f.Trash([]string{"site-copy"})
	if err != nil || !strings.HasPrefix(trash, ".trash/20261101-120000-") {
		t.Fatalf("trash: %q %v", trash, err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(trash), "site-copy", "index.php")); err != nil {
		t.Fatal("trashed folder not kept in the trash")
	}
	if _, err := f.Trash([]string{trash}); !errors.Is(err, ErrInvalid) {
		t.Errorf("trashing the trash: %v", err)
	}
	if _, err := f.Trash([]string{""}); !errors.Is(err, ErrInvalid) {
		t.Errorf("trashing the home: %v", err)
	}
	hits, _, err := f.Search("", "NOTES")
	if err != nil || len(hits) != 1 || hits[0].Path != "public_html/notes.txt" {
		t.Fatalf("search (the trash is left out): %+v %v", hits, err)
	}
	u, err := f.DiskUsage("")
	i := slices.IndexFunc(u.Children, func(e Entry) bool { return e.Name == "public_html" })
	if err != nil || i < 0 || u.Children[i].Size != 18 || u.Total != 36 || u.Largest[0].Name != "index.php" {
		t.Fatalf("usage: %+v %v", u, err)
	}
	if runtime.GOOS == "linux" {
		if err := f.Chmod("public_html", 0o750, true); err != nil {
			t.Fatal(err)
		}
		if e, _ := f.Stat("public_html/index.php"); e.Mode != "0750" {
			t.Errorf("chmod -R: %s", e.Mode)
		}
	}
}

func TestTextEncodings(t *testing.T) {
	f, _ := newFS(t)
	if _, err := f.WriteText("latin.txt", Text{Content: "café", Encoding: "iso-8859-1"}); err != nil {
		t.Fatal(err)
	}
	got, err := f.ReadText("latin.txt", "")
	if err != nil || got.Content != "café" || got.Encoding != "windows-1252" {
		t.Fatalf("guessed: %+v %v", got, err)
	}
	if _, err := f.ReadText("latin.txt", "utf-8"); !errors.Is(err, ErrInvalid) {
		t.Errorf("not UTF-8: %v", err)
	}
	if _, err := f.WriteText("x.txt", Text{Content: "日本", Encoding: "iso-8859-1"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unencodable: %v", err)
	}
	write(t, f, "bin.dat", "a\x00b")
	if _, err := f.ReadText("bin.dat", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("binary: %v", err)
	}
}

func TestArchives(t *testing.T) {
	f, dir := newFS(t)
	write(t, f, "site/a.txt", "A")
	write(t, f, "site/sub/b.txt", "B")
	for _, format := range []string{"zip", "tar.gz"} {
		name := "site." + format
		if _, err := f.Compress([]string{"site"}, name, format); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		out := "out-" + strings.ReplaceAll(format, ".", "-")
		if _, err := f.Extract(name, out); err != nil {
			t.Fatalf("extract %s: %v", format, err)
		}
		if b, err := os.ReadFile(filepath.Join(dir, out, "site", "sub", "b.txt")); err != nil || string(b) != "B" {
			t.Fatalf("%s round trip: %q %v", format, b, err)
		}
		if _, err := f.Extract(name, out); !errors.Is(err, ErrExists) {
			t.Errorf("extract onto an existing folder: %v", err)
		}
	}
	// An archive with an entry leaving its folder is refused and leaves nothing.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("ok.txt")
	w.Write([]byte("ok"))
	w, _ = zw.Create("../../evil.txt")
	w.Write([]byte("evil"))
	zw.Close()
	write(t, f, "evil.zip", buf.String())
	if _, err := f.Extract("evil.zip", "evil"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("evil zip: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused archive left its folder")
	}
	if _, err := f.Compress([]string{"site"}, "site/inside.zip", "zip"); !errors.Is(err, ErrInvalid) {
		t.Errorf("archive inside what it packs: %v", err)
	}
}

func TestHandler(t *testing.T) {
	f, _ := newFS(t)
	touched := 0
	h := Handler(f, func() { touched++ })
	do := func(method, target, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
		return rec
	}
	if rec := do("PUT", "/v1/upload?path=a.txt", "hello"); rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	if rec := do("GET", "/v1/download?path=a.txt", ""); rec.Body.String() != "hello" || rec.Header().Get("Content-Length") != "5" {
		t.Fatalf("download: %q", rec.Body)
	}
	if rec := do("GET", "/v1/list?path=../x", ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"invalid"`) {
		t.Fatalf("bad path: %d %s", rec.Code, rec.Body)
	}
	if rec := do("GET", "/v1/stat?path=nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", rec.Code)
	}
	if rec := do("POST", "/v1/chmod", `{"path":"a.txt","mode":"9x9"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", rec.Code)
	}
	if touched != 5 {
		t.Errorf("touched %d times", touched)
	}
}
