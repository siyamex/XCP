package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanRel(t *testing.T) {
	ok := map[string]string{
		"":                 ".",
		".":                ".",
		"a":                "a",
		"a/b/":             "a/b",
		"a//b/./c":         "a/b/c",
		"public_html/x.js": "public_html/x.js",
		"..a/b..":          "..a/b..",
	}
	for in, want := range ok {
		got, err := CleanRel(in)
		if err != nil || got != want {
			t.Errorf("CleanRel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"/etc/passwd", "..", "../x", "a/../../x", "a/..", "a\\b", "a\x00b",
		strings.Repeat("a", MaxNameLen+1),
		strings.Repeat("a/", MaxPathLen/2+1),
	}
	for _, in := range bad {
		if got, err := CleanRel(in); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("CleanRel(%q) = %q, %v; want ErrInvalidPath", in, got, err)
		}
	}
}

func FuzzCleanRel(f *testing.F) {
	for _, s := range []string{"", "a/b", "../x", "/abs", "a/./b//c", "a\\..\\b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := CleanRel(in)
		if err != nil {
			return
		}
		if strings.HasPrefix(got, "/") || got == ".." || strings.HasPrefix(got, "../") ||
			strings.Contains(got, "/../") || strings.HasSuffix(got, "/..") || strings.ContainsAny(got, "\x00\\") {
			t.Fatalf("CleanRel(%q) = %q escapes or is unclean", in, got)
		}
		if again, err := CleanRel(got); err != nil || again != got {
			t.Fatalf("CleanRel not idempotent: %q -> %q -> %q, %v", in, got, again, err)
		}
	})
}

func openTestRoot(t *testing.T) (*Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

func TestBasicOperations(t *testing.T) {
	r, dir := openTestRoot(t)

	if err := r.MkdirAll("public_html/assets", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.MkdirAll("public_html/assets", 0o755); err != nil {
		t.Fatalf("MkdirAll not idempotent: %v", err)
	}
	if err := r.WriteFileAtomic("public_html/index.html", []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFileAtomic("public_html/index.html", []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := r.ReadFile("public_html/index.html", 1024)
	if err != nil || string(b) != "v2" {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	if _, err := r.ReadFile("public_html/index.html", 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile limit: err = %v", err)
	}

	ents, err := r.ReadDir("public_html")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 || ents[0].Name() != "assets" || ents[1].Name() != "index.html" {
		t.Fatalf("ReadDir = %v (temp files must not be left behind)", ents)
	}

	if err := r.Rename("public_html/index.html", "public_html/assets/index.html"); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFileAtomic("public_html/b.txt", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Rename("public_html/b.txt", "public_html/assets/index.html"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Rename over existing file: err = %v, want ErrExist", err)
	}
	if err := r.Remove("public_html/assets/index.html"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("public_html/assets"); err != nil {
		t.Fatalf("remove empty dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "public_html", "assets")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dir still exists: %v", err)
	}
}

func TestRefusesRootAndBadInput(t *testing.T) {
	r, _ := openTestRoot(t)
	for name, err := range map[string]error{
		"remove root":   r.Remove("."),
		"rename root":   r.Rename("", "x"),
		"write root":    r.WriteFileAtomic(".", nil, 0o644),
		"dotdot":        r.Mkdir("../x", 0o755),
		"absolute":      r.Mkdir("/tmp/x", 0o755),
		"setuid":        r.Chmod("x", 0o4755),
		"chmod missing": r.Chmod("missing", 0o644),
	} {
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
