package userfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestTrashRestoreAndEmpty(t *testing.T) {
	f, dir := newFS(t)
	write(t, f, "public_html/index.php", "<?php")
	write(t, f, "public_html/css/site.css", "body{}")
	write(t, f, "docs/notes.txt", "notes")
	write(t, f, "docs/old/a.txt", "a")

	b1, err := f.Trash([]string{"public_html/css", "docs/notes.txt"})
	if err != nil {
		t.Fatal(err)
	}
	f.Now = func() time.Time { return time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC) }
	b2, err := f.Trash([]string{"docs/old"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := f.TrashList()
	if err != nil || len(list) != 2 || ".trash/"+list[0].ID != b2 {
		t.Fatalf("list: %+v %v (batches %s %s)", list, err, b1, b2)
	}
	if list[0].Time.Hour() != 13 || len(list[1].Items) != 2 {
		t.Errorf("batches: %+v", list)
	}
	byName := map[string]TrashItem{}
	for _, it := range list[1].Items {
		byName[it.Name] = it
	}
	if byName["css"].Origin != "public_html/css" || byName["css"].Type != "dir" || byName["notes.txt"].Origin != "docs/notes.txt" || byName["notes.txt"].Size != 5 {
		t.Errorf("items: %+v", byName)
	}

	// Put one back; the other stays.
	res, err := f.TrashRestore(list[1].ID, []string{"notes.txt"})
	if err != nil || !slices.Equal(res.Restored, []string{"notes.txt"}) || len(res.Conflicts) != 0 {
		t.Fatalf("restore: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "docs", "notes.txt")); string(b) != "notes" {
		t.Errorf("restored content %q", b)
	}
	list, _ = f.TrashList()
	if len(list) != 2 || len(list[1].Items) != 1 || list[1].Items[0].Name != "css" {
		t.Errorf("after one restore: %+v", list)
	}

	// Something there already: it is not replaced, the item stays in the trash.
	write(t, f, "public_html/css/new.css", "new")
	res, err = f.TrashRestore(list[1].ID, nil)
	if err != nil || len(res.Restored) != 0 || !slices.Equal(res.Conflicts, []string{"css"}) {
		t.Fatalf("conflict: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "public_html", "css", "new.css")); string(b) != "new" {
		t.Error("the restore replaced what was there")
	}
	// Its folder gone: it is made again.
	if _, err := f.Trash([]string{"public_html/css"}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "docs")); err != nil {
		t.Fatal(err)
	}
	id2 := b2[len(".trash/"):]
	res, err = f.TrashRestore(id2, nil) // the batch that holds docs/old
	if err != nil || len(res.Restored) != 1 {
		t.Fatalf("restore into a missing folder: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "docs", "old", "a.txt")); string(b) != "a" {
		t.Errorf("docs/old not back: %q", b)
	}
	list, _ = f.TrashList()
	if slices.ContainsFunc(list, func(b TrashBatch) bool { return b.ID == id2 }) {
		t.Error("an emptied batch is still listed")
	}

	// Bad ids and names.
	for _, id := range []string{"", "../x", "20261101-120000", ".trash"} {
		if _, err := f.TrashRestore(id, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("restore of %q: %v", id, err)
		}
		if _, err := f.TrashEmpty([]string{id}); !errors.Is(err, ErrInvalid) {
			t.Errorf("empty of %q: %v", id, err)
		}
	}
	list, _ = f.TrashList()
	for _, name := range []string{"../x", "a/b", originFile, ""} {
		if _, err := f.TrashRestore(list[0].ID, []string{name}); !errors.Is(err, ErrInvalid) {
			t.Errorf("restore of the name %q: %v", name, err)
		}
	}

	// Empty one batch, then everything. A folder with no permissions still goes.
	if err := os.Chmod(filepath.Join(dir, ".trash", list[0].ID), 0o700); err != nil {
		t.Fatal(err)
	}
	n, err := f.TrashEmpty([]string{list[0].ID})
	if err != nil || n != 1 {
		t.Fatalf("empty one: %d %v", n, err)
	}
	n, err = f.TrashEmpty(nil)
	if err != nil || n != len(list)-1 {
		t.Fatalf("empty all: %d %v", n, err)
	}
	if list, _ = f.TrashList(); len(list) != 0 {
		t.Errorf("not empty: %+v", list)
	}
	// Nothing outside the trash was touched.
	if _, err := os.Stat(filepath.Join(dir, "public_html", "index.php")); err != nil {
		t.Error("emptying the trash removed a file outside it")
	}
	// An old batch without a memory of origins goes back to the home folder.
	old := filepath.Join(dir, ".trash", "20250101-000000-abcdefabcdef")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "legacy.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = f.TrashRestore("20250101-000000-abcdefabcdef", nil)
	if err != nil || len(res.Restored) != 1 {
		t.Fatalf("legacy batch: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "legacy.txt")); err != nil {
		t.Error("legacy item not in the home folder")
	}
}
