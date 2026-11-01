package userfs

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/bodgit/sevenzip"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
)

// Limits of unpacking: the disk quota counts too, these stop archive bombs
// before they fill it.
const (
	MaxExtractBytes = 20 << 30
	MaxExtractFiles = 100_000
)

// Encodings the editor can read and write besides UTF-8.
var encodings = map[string]encoding.Encoding{
	"iso-8859-1":   charmap.ISO8859_1,
	"iso-8859-15":  charmap.ISO8859_15,
	"windows-1252": charmap.Windows1252,
}

// Text is a file opened in the editor.
type Text struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"` // utf-8, iso-8859-1, iso-8859-15, windows-1252
}

// ReadText reads a file for the editor in an encoding ("" guesses: UTF-8
// when valid, else windows-1252).
func (f *FS) ReadText(p, enc string) (Text, error) {
	c, err := cleanNonRoot(p)
	if err != nil {
		return Text{}, err
	}
	b, err := f.root.ReadFile(c, MaxTextFile)
	if errors.Is(err, fsxTooLarge) {
		return Text{}, fmt.Errorf("%w: the editor opens files up to %d MB", ErrTooLarge, MaxTextFile>>20)
	}
	if err != nil {
		return Text{}, mapErr(err)
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return Text{}, invalid("%s is not a text file", c)
	}
	if enc == "" {
		enc = "utf-8"
		if !utf8.Valid(b) {
			enc = "windows-1252"
		}
	}
	if enc == "utf-8" {
		if !utf8.Valid(b) {
			return Text{}, invalid("%s is not UTF-8; choose its encoding", c)
		}
		return Text{Content: string(b), Encoding: enc}, nil
	}
	e, ok := encodings[enc]
	if !ok {
		return Text{}, invalid("unknown encoding %q", enc)
	}
	s, err := e.NewDecoder().Bytes(b)
	if err != nil {
		return Text{}, invalid("%s is not %s", c, enc)
	}
	return Text{Content: string(s), Encoding: enc}, nil
}

// WriteText saves the editor's text in an encoding.
func (f *FS) WriteText(p string, t Text) (Entry, error) {
	b := []byte(t.Content)
	switch t.Encoding {
	case "", "utf-8":
	default:
		e, ok := encodings[t.Encoding]
		if !ok {
			return Entry{}, invalid("unknown encoding %q", t.Encoding)
		}
		var err error
		if b, err = e.NewEncoder().Bytes(b); err != nil {
			return Entry{}, invalid("the text has characters %s cannot hold", t.Encoding)
		}
	}
	if len(b) > MaxTextFile {
		return Entry{}, fmt.Errorf("%w: the editor saves files up to %d MB", ErrTooLarge, MaxTextFile>>20)
	}
	return f.Write(p, bytes.NewReader(b), true, -1)
}

// Compress packs paths (all in one folder) into a new archive at to:
// "zip" or "tar.gz". Links are left out.
func (f *FS) Compress(paths []string, to, format string) (Entry, error) {
	dst, err := cleanNonRoot(to)
	if err != nil {
		return Entry{}, err
	}
	if len(paths) == 0 {
		return Entry{}, invalid("choose what to pack")
	}
	var srcs []string
	for _, p := range paths {
		c, err := cleanNonRoot(p)
		if err != nil {
			return Entry{}, err
		}
		if c == dst || strings.HasPrefix(dst, c+"/") {
			return Entry{}, invalid("the archive cannot be inside what it packs")
		}
		srcs = append(srcs, c)
	}
	pr, pw := io.Pipe()
	go func() {
		var err error
		switch format {
		case "zip":
			err = f.writeZip(pw, srcs)
		case "tar.gz":
			err = f.writeTarGz(pw, srcs)
		default:
			err = invalid("format is zip or tar.gz")
		}
		pw.CloseWithError(err)
	}()
	e, err := f.Write(dst, pr, false, -1)
	_ = pr.CloseWithError(err)
	return e, err
}

// each calls fn for every folder and file below srcs, with its name in the archive.
func (f *FS) each(srcs []string, fn func(p, name string, fi fs.FileInfo) error) error {
	for _, src := range srcs {
		base := path.Dir(src)
		err := f.walk(src, func(p string, fi fs.FileInfo) error {
			if !fi.IsDir() && !fi.Mode().IsRegular() {
				return nil
			}
			name := p
			if base != "." {
				name = strings.TrimPrefix(p, base+"/")
			}
			return fn(p, name, fi)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FS) writeZip(w io.Writer, srcs []string) error {
	zw := zip.NewWriter(w)
	err := f.each(srcs, func(p, name string, fi fs.FileInfo) error {
		h, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		h.Name, h.Method = name, zip.Deflate
		if fi.IsDir() {
			h.Name += "/"
			_, err = zw.CreateHeader(h)
			return err
		}
		out, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		return f.copyOut(p, out)
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

func (f *FS) writeTarGz(w io.Writer, srcs []string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := f.each(srcs, func(p, name string, fi fs.FileInfo) error {
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname, h.Uid, h.Gid = name, "", "", 0, 0
		if fi.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		return f.copyOut(p, tw)
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func (f *FS) copyOut(p string, w io.Writer) error {
	src, err := f.root.Open(p)
	if err != nil {
		return mapErr(err)
	}
	defer src.Close()
	_, err = io.Copy(w, src)
	return err
}

// unpacker writes an archive's entries below one folder, with limits.
type unpacker struct {
	f            *FS
	dir          string
	files, bytes int64
}

// path checks an entry's name and returns where it goes.
func (u *unpacker) path(name string) (string, error) {
	name = strings.TrimSuffix(strings.ReplaceAll(name, `\`, "/"), "/")
	if name == "" || name == "." {
		return "", nil
	}
	if !fs.ValidPath(name) {
		return "", invalid("the archive has an entry %q that leaves its folder", name)
	}
	return join(u.dir, name), nil
}

func (u *unpacker) mkdir(name string) error {
	p, err := u.path(name)
	if err != nil || p == "" {
		return err
	}
	return mapErr(u.f.root.MkdirAll(p, 0o755))
}

func (u *unpacker) file(name string, mode fs.FileMode, r io.Reader) error {
	p, err := u.path(name)
	if err != nil || p == "" {
		return err
	}
	if u.files++; u.files > MaxExtractFiles {
		return fmt.Errorf("%w: the archive has more than %d files", ErrTooMany, MaxExtractFiles)
	}
	if dir := path.Dir(p); dir != "." {
		if err := u.f.root.MkdirAll(dir, 0o755); err != nil {
			return mapErr(err)
		}
	}
	out, err := u.f.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, (mode.Perm()|0o600)&0o755)
	if err != nil {
		return mapErr(err)
	}
	n, err := io.Copy(out, io.LimitReader(r, MaxExtractBytes-u.bytes+1))
	u.bytes += n
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && u.bytes > MaxExtractBytes {
		err = fmt.Errorf("%w: the archive unpacks to more than %d GB", ErrTooLarge, MaxExtractBytes>>30)
	}
	return err
}

// Extract unpacks an archive (zip, tar, tar.gz, tgz, tar.zst, 7z) into the
// folder to, which must not exist yet: nothing is overwritten, and a
// failed unpack leaves no half-filled folder behind. Links and devices in
// the archive are skipped.
func (f *FS) Extract(p, to string) (Entry, error) {
	src, err := cleanNonRoot(p)
	if err != nil {
		return Entry{}, err
	}
	dst, err := cleanNonRoot(to)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.root.Lstat(dst); err == nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrExists, dst)
	}
	file, _, err := f.OpenRead(src)
	if err != nil {
		return Entry{}, err
	}
	defer file.Close()
	if err := f.root.MkdirAll(dst, 0o755); err != nil {
		return Entry{}, mapErr(err)
	}
	u := &unpacker{f: f, dir: dst}
	lower := strings.ToLower(src)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		err = u.zip(file)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		var gz *gzip.Reader
		if gz, err = gzip.NewReader(file); err == nil {
			err = u.tar(gz)
		}
	case strings.HasSuffix(lower, ".tar.zst"), strings.HasSuffix(lower, ".tzst"):
		var zr *zstd.Decoder
		if zr, err = zstd.NewReader(file); err == nil {
			err = u.tar(zr)
			zr.Close()
		}
	case strings.HasSuffix(lower, ".tar"):
		err = u.tar(file)
	case strings.HasSuffix(lower, ".7z"):
		err = u.sevenZip(file)
	default:
		err = invalid("unpacks .zip, .tar, .tar.gz, .tgz, .tar.zst and .7z")
	}
	if err != nil {
		_ = f.removeAll(dst)
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrTooLarge) || errors.Is(err, ErrTooMany) {
			return Entry{}, err
		}
		return Entry{}, invalid("cannot unpack %s: %v", src, err)
	}
	return f.Stat(dst)
}

func (u *unpacker) zip(file *os.File) error {
	fi, err := file.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(file, fi.Size())
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		switch m := zf.Mode(); {
		case m.IsDir():
			err = u.mkdir(zf.Name)
		case m.IsRegular():
			var rc io.ReadCloser
			if rc, err = zf.Open(); err == nil {
				err = u.file(zf.Name, m, rc)
				rc.Close()
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *unpacker) tar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = u.mkdir(h.Name)
		case tar.TypeReg:
			err = u.file(h.Name, fs.FileMode(h.Mode), tr) //nolint:gosec // G115: masked to 0755 in file
		}
		if err != nil {
			return err
		}
	}
}

func (u *unpacker) sevenZip(file *os.File) error {
	fi, err := file.Stat()
	if err != nil {
		return err
	}
	zr, err := sevenzip.NewReader(file, fi.Size())
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		switch m := zf.Mode(); {
		case m.IsDir():
			err = u.mkdir(zf.Name)
		case m.IsRegular():
			var rc io.ReadCloser
			if rc, err = zf.Open(); err == nil {
				err = u.file(zf.Name, m, rc)
				rc.Close()
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// removeAll removes a folder and everything in it (a failed unpack).
func (f *FS) removeAll(p string) error {
	var all []string
	if err := f.walk(p, func(p string, _ fs.FileInfo) error {
		all = append(all, p)
		return nil
	}); err != nil {
		return err
	}
	for i := len(all) - 1; i >= 0; i-- {
		if err := f.root.Remove(all[i]); err != nil {
			return err
		}
	}
	return nil
}
