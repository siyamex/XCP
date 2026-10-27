package execx

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestNewRunnerRejectsRelativeOrUncleanPaths(t *testing.T) {
	for _, p := range []string{"sh", "bin/sh", "/usr/bin/../bin/sh", "/usr/bin/"} {
		if _, err := NewRunner(p); err == nil {
			t.Errorf("NewRunner(%q) accepted a bad path", p)
		}
	}
}

func TestRunRefusesBinaryNotOnAllowList(t *testing.T) {
	dir := t.TempDir() // absolute on every OS
	r, err := NewRunner(filepath.Join(dir, "true"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Run(context.Background(), Cmd{Path: filepath.Join(dir, "false")})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
}

func TestCapWriterTruncates(t *testing.T) {
	w := &capWriter{limit: 4}
	n, err := w.Write([]byte("abcdef"))
	if err != nil || n != 6 {
		t.Fatalf("Write = %d, %v; want 6, nil (must not fail the child)", n, err)
	}
	w.Write([]byte("gh"))
	if got := w.buf.String(); got != "abcd" || !w.truncated {
		t.Fatalf("buf = %q truncated=%v", got, w.truncated)
	}
}
