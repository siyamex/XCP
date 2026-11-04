package agent

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Limits of restoring a backup (ADR-0015).
const (
	RestoreMaxAccountJSON = 64 << 20
	RestoreMaxEntries     = 5_000_000
	restoreMaxName        = 4096
	MariaDBClientPath     = "/usr/bin/mariadb"
)

// RestorePlan is what reading a backup tells: its settings and databases,
// after every file matched the checksum in its manifest.
type RestorePlan struct {
	AccountJSON []byte
	Databases   []string
	Files       int64
	Bytes       int64
	Panel       string
}

// archive opens a backup of the account for reading.
func (b *Backups) archive(username, file string) (*tar.Reader, func(), error) {
	if validate.Username(username) != nil {
		return nil, nil, invalid("%q is not an account name", username)
	}
	if err := CheckBackupFile(username, file); err != nil {
		return nil, nil, err
	}
	dir, err := fsx.OpenRoot(filepath.Join(b.Dir, username))
	if err != nil {
		return nil, nil, err
	}
	f, err := dir.Open(file)
	if err != nil {
		dir.Close()
		return nil, nil, err
	}
	zr, err := zstd.NewReader(f, zstd.WithDecoderMaxMemory(256<<20))
	if err != nil {
		f.Close()
		dir.Close()
		return nil, nil, err
	}
	return tar.NewReader(zr), func() { zr.Close(); f.Close(); dir.Close() }, nil
}

// Inspect reads a whole backup and checks it against its manifest: format,
// account, every file's SHA-256, no entry the manifest does not list, none
// outside homedir/, mysql/ and the two json files. Nothing is written.
func (b *Backups) Inspect(username, file string) (RestorePlan, error) {
	tr, closeArchive, err := b.archive(username, file)
	if err != nil {
		return RestorePlan{}, err
	}
	defer closeArchive()
	var plan RestorePlan
	var manifest *BackupManifest
	sums := map[string]string{}
	for entries := 0; ; entries++ {
		if entries > RestoreMaxEntries {
			return plan, invalid("the backup has too many entries")
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return plan, invalid("the backup is damaged: %v", err)
		}
		name := hdr.Name
		switch {
		case name == "manifest.json":
			m, err := io.ReadAll(io.LimitReader(tr, 1<<20+1))
			if err != nil || len(m) > 1<<20 {
				return plan, invalid("the manifest is damaged or too big")
			}
			manifest = &BackupManifest{}
			if err := json.Unmarshal(m, manifest); err != nil {
				return plan, invalid("the manifest is damaged: %v", err)
			}
		case name == "account.json":
			data, err := io.ReadAll(io.LimitReader(tr, RestoreMaxAccountJSON+1))
			if err != nil || len(data) > RestoreMaxAccountJSON {
				return plan, invalid("account.json is damaged or too big")
			}
			plan.AccountJSON = data
			h := sha256.Sum256(data)
			sums[name] = hex.EncodeToString(h[:])
		case name == "homedir" || strings.HasPrefix(name, "homedir/"):
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			h := sha256.New()
			n, err := io.Copy(h, tr)
			if err != nil {
				return plan, invalid("the backup is damaged: %v", err)
			}
			plan.Files++
			plan.Bytes += n
			sums[name] = hex.EncodeToString(h.Sum(nil))
		case strings.HasPrefix(name, "mysql/") && strings.HasSuffix(name, ".sql") && hdr.Typeflag == tar.TypeReg:
			db := strings.TrimSuffix(strings.TrimPrefix(name, "mysql/"), ".sql")
			if err := CheckMySQLName(username, db, MaxDatabaseName); err != nil {
				return plan, err
			}
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return plan, invalid("the backup is damaged: %v", err)
			}
			sums[name] = hex.EncodeToString(h.Sum(nil))
			plan.Databases = append(plan.Databases, db)
		default:
			return plan, invalid("the backup has an unexpected entry %q", name)
		}
	}
	switch {
	case manifest == nil:
		return plan, invalid("the backup has no manifest")
	case manifest.Format != BackupFormat:
		return plan, invalid("the backup is format %d; this server restores format %d", manifest.Format, BackupFormat)
	case manifest.Username != username:
		return plan, invalid("the backup is of account %q", manifest.Username)
	case plan.AccountJSON == nil:
		return plan, invalid("the backup has no account.json")
	}
	for name, want := range manifest.Entries {
		if sums[name] != want {
			return plan, invalid("%s does not match its checksum: the backup is damaged", name)
		}
	}
	for name := range sums {
		if _, ok := manifest.Entries[name]; !ok {
			return plan, invalid("%s is not in the manifest", name)
		}
	}
	plan.Panel = manifest.Panel
	return plan, nil
}

// safeRel returns name below prefix when it is a clean relative path.
func safeRel(name, prefix string) (string, bool) {
	rel, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return "", false
	}
	rel = strings.TrimSuffix(rel, "/")
	if rel == "" || len(rel) > restoreMaxName || strings.ContainsRune(rel, 0) || strings.ContainsRune(rel, '\\') ||
		path.IsAbs(rel) || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// homeEntries copies the safe entries of homedir/ into w as a tar stream
// of names relative to the home: files, folders, symlinks and hard links
// inside it; no setuid or setgid bits, no owners, nothing else.
func homeEntries(tr *tar.Reader, w io.Writer) (int64, error) {
	tw := tar.NewWriter(w)
	var n int64
	for entries := 0; ; entries++ {
		if entries > RestoreMaxEntries {
			return n, invalid("the backup has too many entries")
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return n, tw.Close()
		}
		if err != nil {
			return n, err
		}
		rel, ok := safeRel(hdr.Name, "homedir/")
		if !ok {
			continue // account.json, mysql/, the folder itself, anything unsafe
		}
		out := &tar.Header{Name: rel, Mode: hdr.Mode &^ 0o6000, ModTime: hdr.ModTime, Typeflag: hdr.Typeflag, Format: tar.FormatPAX}
		switch hdr.Typeflag {
		case tar.TypeDir:
			out.Name = rel + "/"
		case tar.TypeReg:
			out.Size = hdr.Size
		case tar.TypeSymlink:
			out.Linkname = hdr.Linkname
		case tar.TypeLink:
			target, ok := safeRel(hdr.Linkname, "homedir/")
			if !ok {
				continue
			}
			out.Linkname = target
		default:
			continue
		}
		if err := tw.WriteHeader(out); err != nil {
			return n, err
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := io.Copy(tw, tr); err != nil {
				return n, err
			}
		}
		n++
	}
}

// RestoreHome puts a backup's home folder back into the account's home.
// The files are unpacked by tar running as the account's user in its slice,
// so nothing can be written that the user could not write.
func (b *Backups) RestoreHome(ctx context.Context, username, file string) (int64, error) {
	uid, gid, home, err := b.account(username)
	if err != nil {
		return 0, err
	}
	tr, closeArchive, err := b.archive(username, file)
	if err != nil {
		return 0, err
	}
	defer closeArchive()
	removePlaceholders(home)
	pr, pw := io.Pipe()
	type filtered struct {
		n   int64
		err error
	}
	done := make(chan filtered, 1)
	go func() {
		n, err := homeEntries(tr, pw)
		pw.CloseWithError(err)
		done <- filtered{n, err}
	}()
	res, runErr := b.Run.Run(ctx, execx.Cmd{
		Path: SystemdRunPath, Stdin: pr, Timeout: backupMaxRuntime, MaxOutput: 256 << 10,
		Args: []string{
			"--wait", "--pipe", "--quiet", "--collect", "--service-type=exec",
			"--unit=xcp-restore-" + username + ".service", "--slice=" + SliceName(username),
			"--uid=" + strconv.Itoa(uid), "--gid=" + strconv.Itoa(gid), "--working-directory=" + home,
			"--property=RuntimeMaxSec=" + strconv.Itoa(int(backupMaxRuntime.Seconds())),
			"--", "/usr/bin/tar", "--extract", "--file=-", "--directory=" + home,
			"--no-same-owner", "--same-permissions", "--no-overwrite-dir", "--delay-directory-restore",
		},
	})
	pr.Close() // stops the filter if tar quit early
	f := <-done
	switch {
	case f.err != nil && !errors.Is(f.err, io.ErrClosedPipe):
		return 0, fmt.Errorf("read the backup: %w", f.err)
	case runErr != nil:
		return 0, fmt.Errorf("unpack the files: %w: %s", runErr, strings.TrimSpace(string(res.Stderr)))
	}
	return f.n, nil
}

// RestoreDatabases loads the backup's database dumps. MariaDB runs them as
// a temporary user that may use that one database only, so a dump cannot
// reach anything else.
func (b *Backups) RestoreDatabases(ctx context.Context, username, file string, m *MySQL) ([]string, error) {
	if _, _, _, err := b.account(username); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("the database server is not installed: %w", ErrNotInstalled)
	}
	tr, closeArchive, err := b.archive(username, file)
	if err != nil {
		return nil, err
	}
	defer closeArchive()
	var done []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return done, nil
		}
		if err != nil {
			return done, err
		}
		if !strings.HasPrefix(hdr.Name, "mysql/") || !strings.HasSuffix(hdr.Name, ".sql") || hdr.Typeflag != tar.TypeReg {
			continue
		}
		db := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "mysql/"), ".sql")
		if err := CheckMySQLName(username, db, MaxDatabaseName); err != nil {
			return done, err
		}
		if err := m.RestoreDump(ctx, b.Run, db, tr); err != nil {
			return done, fmt.Errorf("restore database %s: %w", db, err)
		}
		done = append(done, db)
	}
}

var definerRe = regexp.MustCompile("\\s*DEFINER=`[^`]*`@`[^`]*`")

// definitionLine reports whether a dump line creates a routine, trigger,
// view or event: the lines that name a DEFINER.
func definitionLine(l []byte) bool {
	s := string(l[:min(len(l), 40)])
	return strings.HasPrefix(s, "/*!50003 CREATE") || strings.HasPrefix(s, "/*!50106 CREATE") ||
		strings.HasPrefix(s, "/*!50001 CREATE") || strings.HasPrefix(s, "CREATE DEFINER") || strings.HasPrefix(s, "/*!50017 DEFINER")
}

// stripDefiners copies a dump, removing DEFINER clauses from the lines
// that define routines, triggers, views and events: the temporary user
// cannot create objects for someone else, and they belong to the account's
// own user anyway. Data lines pass through untouched, however long.
func stripDefiners(dst io.Writer, src io.Reader) error {
	br := bufio.NewReaderSize(src, 1<<20)
	midLine := false
	for {
		line, err := br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return err
		}
		out := line
		if !midLine && definitionLine(line) {
			out = definerRe.ReplaceAll(line, nil)
		}
		if _, werr := dst.Write(out); werr != nil {
			return werr
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			midLine = true
		case errors.Is(err, io.EOF):
			return nil
		default:
			midLine = false
		}
	}
}

// removePlaceholders deletes the placeholder pages that creating the
// account just wrote, so they do not hide the restored site's own index
// file (Apache serves index.html before index.php). Only a file that is
// still exactly such a page goes, and only in the folders up to two levels
// below the home folder.
func removePlaceholders(home string) {
	root, err := fsx.OpenRoot(home)
	if err != nil {
		return
	}
	defer root.Close()
	var visit func(dir string, depth int)
	visit = func(dir string, depth int) {
		ents, err := root.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			rel := path.Join(dir, e.Name())
			switch {
			case e.Type().IsRegular() && e.Name() == "index.html":
				if data, err := root.ReadFile(rel, 1024); err == nil && bytes.Contains(data, []byte("is hosted with XCP.")) {
					_ = root.Remove(rel)
				}
			case e.IsDir() && depth < 2:
				visit(rel, depth+1)
			}
		}
	}
	visit(".", 0)
}
