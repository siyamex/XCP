package agent

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
)

// Database dumps in an account's home (USR-DB-07).
const (
	DumpDir      = "db-dumps" // where exports go, in the home
	MaxDumpFiles = 20         // exports are refused while the folder holds this many files
)

var dumpExts = []string{".sql.gz", ".sql.zst", ".sql"}

// CheckDumpPath cleans the path of a dump inside an account's home and
// checks its ending. The fake agent and the panel use it too.
func CheckDumpPath(rel string) (string, error) {
	clean, err := fsx.CleanRel(strings.TrimPrefix(strings.TrimSpace(rel), "/"))
	if err != nil || clean == "." || clean == "" {
		return "", invalid("%q is not a file in the home folder", rel)
	}
	for _, e := range dumpExts {
		if strings.HasSuffix(strings.ToLower(clean), e) {
			return clean, nil
		}
	}
	return "", invalid("a dump is a .sql, .sql.gz or .sql.zst file")
}

// ExportDatabase dumps one of the account's databases into a new gzip file
// in db-dumps of its home and returns the file's path in the home and its
// size. The file belongs to the account's user. The dump has no CREATE
// DATABASE or USE, so it can be imported into a database of another name.
func (b *Backups) ExportDatabase(ctx context.Context, username, db string) (string, int64, error) {
	if err := CheckMySQLName(username, db, MaxDatabaseName); err != nil {
		return "", 0, err
	}
	uid, gid, home, err := b.account(username)
	if err != nil {
		return "", 0, err
	}
	root, err := fsx.OpenRoot(home)
	if err != nil {
		return "", 0, err
	}
	defer root.Close()
	switch err := root.Mkdir(DumpDir, 0o700); {
	case err == nil:
		if err := root.Chown(DumpDir, uid, gid); err != nil {
			return "", 0, err
		}
	case !errors.Is(err, fs.ErrExist):
		return "", 0, err
	}
	// Root writes past the quota: bound what exports can pile up.
	entries, err := root.ReadDir(DumpDir)
	if err != nil {
		return "", 0, err
	}
	if len(entries) >= MaxDumpFiles {
		return "", 0, invalid("the folder %s holds %d files already: remove old exports first", DumpDir, len(entries))
	}
	rel := DumpDir + "/" + db + "-" + b.now().UTC().Format("20060102T150405Z") + ".sql.gz"
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	fail := func(err error) (string, int64, error) {
		f.Close()
		_ = root.Remove(rel)
		return "", 0, err
	}
	if err := f.Chown(uid, gid); err != nil {
		return fail(err)
	}
	gz := gzip.NewWriter(f)
	res, err := b.Run.Run(ctx, execx.Cmd{
		Path: MariaDBDumpPath, Timeout: backupMaxRuntime, Stdout: gz,
		Args: []string{"--single-transaction", "--routines", "--triggers", "--events", "--hex-blob", "--", db},
	})
	if err != nil {
		return fail(fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res.Stderr))))
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	return rel, fi.Size(), f.Close()
}

// ImportDatabase runs a dump from the account's home in one of its
// databases. The file is opened without following links and must be a
// regular file of the account's user, so the account cannot make root read
// someone else's file. The statements run as a temporary user with rights
// on that one database only.
func (b *Backups) ImportDatabase(ctx context.Context, m *MySQL, username, db, rel string) error {
	if err := CheckMySQLName(username, db, MaxDatabaseName); err != nil {
		return err
	}
	rel, err := CheckDumpPath(rel)
	if err != nil {
		return err
	}
	uid, _, home, err := b.account(username)
	if err != nil {
		return err
	}
	root, err := fsx.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return invalid("cannot open %s: %v", rel, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return invalid("%s is not a file", rel)
	}
	if owner, ok := fileUID(fi); ok && owner != uid {
		return invalid("%s does not belong to the account", rel)
	}
	var dump io.Reader = f
	switch lower := strings.ToLower(rel); {
	case strings.HasSuffix(lower, ".gz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return invalid("%s is not a gzip file: %v", rel, err)
		}
		defer zr.Close()
		dump = zr
	case strings.HasSuffix(lower, ".zst"):
		zr, err := zstd.NewReader(f, zstd.WithDecoderMaxMemory(256<<20))
		if err != nil {
			return invalid("%s is not a zstd file: %v", rel, err)
		}
		defer zr.Close()
		dump = zr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runDump(ctx, b.Run, db, dump, true)
}
