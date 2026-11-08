package userfs

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The trash (ADR-0032): ~/.trash/<time>-<random>/ holds what was deleted in one
// go, with a small file that remembers where each item came from, so it can
// be put back.

const (
	originFile = ".origin.json"
	maxBatches = 500
)

var batchRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{12}$`)

// TrashItem is something in the trash.
type TrashItem struct {
	Name   string `json:"name"`
	Origin string `json:"origin"` // where it was; empty if unknown
	Type   string `json:"type"`   // file, dir, link or other
	Size   int64  `json:"size"`
}

// TrashBatch is what was deleted together.
type TrashBatch struct {
	ID    string      `json:"id"`
	Time  time.Time   `json:"time"`
	Items []TrashItem `json:"items"`
}

// TrashRestoreResult says what went back and what could not.
type TrashRestoreResult struct {
	Restored  []string `json:"restored"`
	Conflicts []string `json:"conflicts"` // something is there already
}

func (f *FS) readOrigins(dir string) map[string]string {
	b, err := f.root.ReadFile(dir+"/"+originFile, 1<<20)
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil || m == nil {
		return map[string]string{}
	}
	return m
}

func (f *FS) writeOrigins(dir string, m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return mapErr(f.root.WriteFileAtomic(dir+"/"+originFile, b, 0o600))
}

// TrashList returns the batches in the trash, newest first.
func (f *FS) TrashList() ([]TrashBatch, error) {
	ents, err := f.root.ReadDir(TrashDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []TrashBatch{}, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	out := []TrashBatch{}
	for _, e := range ents {
		if !e.IsDir() || !batchRe.MatchString(e.Name()) {
			continue
		}
		dir := TrashDir + "/" + e.Name()
		b := TrashBatch{ID: e.Name(), Items: []TrashItem{}}
		b.Time, _ = time.Parse("20060102-150405", e.Name()[:15])
		origins := f.readOrigins(dir)
		items, err := f.root.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, it := range items {
			if it.Name() == originFile {
				continue
			}
			ti := TrashItem{Name: it.Name(), Origin: origins[it.Name()], Type: "file"}
			if fi, err := f.root.Lstat(dir + "/" + it.Name()); err == nil {
				switch {
				case fi.IsDir():
					ti.Type = "dir"
				case fi.Mode()&fs.ModeSymlink != 0:
					ti.Type = "link"
				case fi.Mode().IsRegular():
					ti.Size = fi.Size()
				default:
					ti.Type = "other"
				}
			}
			b.Items = append(b.Items, ti)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > maxBatches {
		out = out[:maxBatches]
	}
	return out, nil
}

func checkBatch(id string) (string, error) {
	if !batchRe.MatchString(id) {
		return "", invalid("%q is not a batch in the trash", id)
	}
	return TrashDir + "/" + id, nil
}

// TrashRestore puts items of one batch back where they came from. Without
// names, everything in it goes back. Whatever has something in its place
// already stays in the trash and is reported.
func (f *FS) TrashRestore(id string, names []string) (TrashRestoreResult, error) {
	dir, err := checkBatch(id)
	if err != nil {
		return TrashRestoreResult{}, err
	}
	origins := f.readOrigins(dir)
	if len(names) == 0 {
		items, err := f.root.ReadDir(dir)
		if err != nil {
			return TrashRestoreResult{}, mapErr(err)
		}
		for _, it := range items {
			if it.Name() != originFile {
				names = append(names, it.Name())
			}
		}
	}
	res := TrashRestoreResult{Restored: []string{}, Conflicts: []string{}}
	for _, n := range names {
		if n == "" || n == originFile || strings.ContainsAny(n, "/\x00") || n == "." || n == ".." {
			return res, invalid("%q is not an item of the trash", n)
		}
		from := dir + "/" + n
		if _, err := f.root.Lstat(from); err != nil {
			return res, mapErr(err)
		}
		to := origins[n]
		if to == "" {
			to = n // an old batch that never remembered: the home folder
		}
		to, err := cleanNonRoot(to)
		if err != nil || to == TrashDir || strings.HasPrefix(to, TrashDir+"/") {
			res.Conflicts = append(res.Conflicts, n)
			continue
		}
		if _, err := f.root.Lstat(to); err == nil {
			res.Conflicts = append(res.Conflicts, n)
			continue
		}
		if parent := path.Dir(to); parent != "." {
			if err := f.root.MkdirAll(parent, 0o755); err != nil {
				res.Conflicts = append(res.Conflicts, n)
				continue
			}
		}
		if err := f.root.Rename(from, to); err != nil {
			return res, mapErr(err)
		}
		delete(origins, n)
		res.Restored = append(res.Restored, n)
	}
	// Tidy: forget what went back, and drop the batch when nothing is left.
	left, _ := f.root.ReadDir(dir)
	remaining := 0
	for _, it := range left {
		if it.Name() != originFile {
			remaining++
		}
	}
	if remaining == 0 {
		_ = f.root.Remove(dir + "/" + originFile)
		_ = f.root.Remove(dir)
	} else {
		_ = f.writeOrigins(dir, origins)
	}
	return res, nil
}

// purge deletes a path and everything below it, counting entries.
func (f *FS) purge(p string, budget *int, depth int) error {
	if *budget <= 0 || depth > 200 {
		return ErrTooMany
	}
	*budget--
	fi, err := f.root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return mapErr(err)
	}
	if fi.IsDir() {
		_ = f.root.Chmod(p, 0o700) // a folder the person made unreadable is still theirs to delete
		ents, err := f.root.ReadDir(p)
		if err != nil {
			return mapErr(err)
		}
		for _, e := range ents {
			if err := f.purge(p+"/"+e.Name(), budget, depth+1); err != nil {
				return err
			}
		}
	}
	return mapErr(f.root.Remove(p))
}

// TrashEmpty deletes batches for good: the given ones, or all without ids.
// It returns how many batches went.
func (f *FS) TrashEmpty(ids []string) (int, error) {
	if len(ids) == 0 {
		bs, err := f.TrashList()
		if err != nil {
			return 0, err
		}
		for _, b := range bs {
			ids = append(ids, b.ID)
		}
	}
	budget := MaxWalkEntries
	n := 0
	for _, id := range ids {
		dir, err := checkBatch(id)
		if err != nil {
			return n, err
		}
		if err := f.purge(dir, &budget, 0); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
