package logd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestReadNew(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	got, off, err := ReadNew(p, Offset{}, false)
	if err != nil || got != nil || off != (Offset{}) {
		t.Fatalf("missing file: %q %+v %v", got, off, err)
	}
	appendTo(t, p, "one\ntwo\nthr")
	got, off, _ = ReadNew(p, off, false)
	if string(got) != "one\ntwo\n" || off.Offset != 8 {
		t.Fatalf("first read: %q %+v", got, off)
	}
	appendTo(t, p, "ee\n")
	if got, off, _ = ReadNew(p, off, false); string(got) != "three\n" {
		t.Fatalf("a line finished later: %q", got)
	}
	if got, _, _ = ReadNew(p, off, false); len(got) != 0 {
		t.Fatalf("nothing new: %q", got)
	}
	// Truncated (copytruncate): from the start again.
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, p, "four\n")
	if got, off, _ = ReadNew(p, off, false); string(got) != "four\n" {
		t.Fatalf("after truncation: %q", got)
	}
	// Seen for the first time with fromEnd: nothing old.
	if got, o, _ := ReadNew(p, Offset{}, true); len(got) != 0 || o.Offset != off.Offset {
		t.Fatalf("fromEnd: %q %+v", got, o)
	}
}

func TestReadNewFollowsARotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no inodes here")
	}
	p := filepath.Join(t.TempDir(), "a.log")
	appendTo(t, p, "one\n")
	_, off, _ := ReadNew(p, Offset{}, false)
	appendTo(t, p, "two\n") // written before the rotation, not read yet
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, p, "three\n")
	got, _, err := ReadNew(p, off, false)
	if err != nil || string(got) != "two\nthree\n" {
		t.Fatalf("after rotation: %q %v", got, err)
	}
}
