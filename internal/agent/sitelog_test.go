package agent

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestTailLines(t *testing.T) {
	var b strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&b, "line %d %s\n", i, strings.Repeat("x", 40))
	}
	b.WriteString("last without newline")
	log := b.String()
	r := strings.NewReader(log)
	got, err := tailLines(r, int64(len(log)), 3, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"line 4998 " + strings.Repeat("x", 40), "line 4999 " + strings.Repeat("x", 40), "last without newline"}
	if !slices.Equal(got, want) {
		t.Fatalf("tail 3: %q", got)
	}
	// Matches across many 64 KiB blocks, lines split by block edges included.
	got, _ = tailLines(r, int64(len(log)), 1000, "line 12")
	if len(got) != 111 || !strings.HasPrefix(got[0], "line 12 ") || !strings.HasPrefix(got[110], "line 1299 ") {
		t.Fatalf("search: %d lines, first %q, last %q", len(got), got[0], got[len(got)-1])
	}
	for _, l := range got {
		if !strings.HasPrefix(l, "line 12") || !strings.HasSuffix(l, "x") {
			t.Fatalf("a broken line: %q", l)
		}
	}
	if got, _ = tailLines(strings.NewReader(""), 0, 10, ""); len(got) != 0 {
		t.Fatalf("empty: %q", got)
	}
}
