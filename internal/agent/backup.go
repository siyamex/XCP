package agent

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Backups makes, reads and removes account backups (ADR-0013).
type Backups struct {
	Run       *execx.Runner
	Dir       string // /var/backups/xcp: one root-only folder per account
	HomesRoot string
	Version   string // the panel's, for the manifest
	Now       func() time.Time
}

// Paths and limits of backups.
const (
	BackupDir         = "/var/backups/xcp"
	MariaDBDumpPath   = "/usr/bin/mariadb-dump"
	BackupFormat      = 1
	BackupMaxRead     = 1 << 20
	backupMaxRuntime  = 12 * time.Hour
	backupMaxSkipped  = 100
	backupPartSuffix  = ".part"
	backupStagingName = ".staging"
)

// BackupRequest is what a backup holds besides the home folder.
type BackupRequest struct {
	Username    string
	AccountJSON []byte   // the panel's view of the account
	Databases   []string // full names; each must start with "<user>_"
}

// BackupResult describes a finished backup.
type BackupResult struct {
	File    string
	Size    int64
	SHA256  string   // of the archive
	Skipped []string // files of the home that could not be read
}

// BackupManifest is the archive's manifest.json.
type BackupManifest struct {
	Format   int               `json:"format"`
	Panel    string            `json:"panel_version"`
	Username string            `json:"username"`
	Created  time.Time         `json:"created"`
	Entries  map[string]string `json:"sha256"` // entry name -> SHA-256 of its content (files only)
}

var backupFileRe = regexp.MustCompile(`^([a-z][a-z0-9]{0,15})-[0-9]{8}T[0-9]{6}Z\.tar\.zst$`)

// CheckBackupFile checks that file is a backup name of the account.
func CheckBackupFile(username, file string) error {
	m := backupFileRe.FindStringSubmatch(file)
	if m == nil || m[1] != username {
		return invalid("%q is not a backup of %s", file, username)
	}
	return nil
}

func (b *Backups) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// account checks the username and finds the account's ids and home.
func (b *Backups) account(username string) (uid, gid int, home string, err error) {
	if validate.Username(username) != nil {
		return 0, 0, "", invalid("%q is not an account name", username)
	}
	u, err := lookup(username)
	if err != nil {
		return 0, 0, "", err
	}
	if u == nil || u.Name != AccountMarker {
		return 0, 0, "", ErrNotOurUser
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, filepath.Join(b.HomesRoot, username), nil
}

// accountDir opens (making it) the account's root-only backup folder.
func (b *Backups) accountDir(username string) (*fsx.Root, error) {
	root, err := fsx.OpenRoot(b.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.Mkdir(username, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return fsx.OpenRoot(filepath.Join(b.Dir, username))
}

// hashingTar writes tar entries and remembers each file's SHA-256.
type hashingTar struct {
	tw   *tar.Writer
	sums map[string]string
}

func (h *hashingTar) file(name string, mode int64, mtime time.Time, size int64, r io.Reader) error {
	if err := h.tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	sum := sha256.New()
	if _, err := io.Copy(h.tw, io.TeeReader(io.LimitReader(r, size), sum)); err != nil {
		return err
	}
	h.sums[name] = hex.EncodeToString(sum.Sum(nil))
	return nil
}

// Create makes a full backup of an account: its home read as the account's
// user, its databases dumped, and the panel's account.json.
func (b *Backups) Create(ctx context.Context, req BackupRequest) (BackupResult, error) {
	uid, gid, home, err := b.account(req.Username)
	if err != nil {
		return BackupResult{}, err
	}
	for _, db := range req.Databases {
		if err := CheckMySQLName(req.Username, db, MaxDatabaseName); err != nil {
			return BackupResult{}, err
		}
	}
	if !json.Valid(req.AccountJSON) {
		return BackupResult{}, invalid("account.json is not JSON")
	}
	dir, err := b.accountDir(req.Username)
	if err != nil {
		return BackupResult{}, err
	}
	defer dir.Close()
	now := b.now().UTC()
	name := req.Username + "-" + now.Format("20060102T150405Z") + ".tar.zst"
	part := name + backupPartSuffix
	f, err := dir.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BackupResult{}, err
	}
	res, err := b.write(ctx, f, dir, req, uid, gid, home, now)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = dir.Remove(part)
		return BackupResult{}, err
	}
	if err := dir.Rename(part, name); err != nil {
		_ = dir.Remove(part)
		return BackupResult{}, err
	}
	res.File = name
	return res, nil
}

func (b *Backups) write(ctx context.Context, f *os.File, dir *fsx.Root, req BackupRequest, uid, gid int, home string, now time.Time) (BackupResult, error) {
	sum := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(f, sum)}
	zw, err := zstd.NewWriter(counted, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return BackupResult{}, err
	}
	ht := &hashingTar{tw: tar.NewWriter(zw), sums: map[string]string{}}
	if err := ht.file("account.json", 0o600, now, int64(len(req.AccountJSON)), strings.NewReader(string(req.AccountJSON))); err != nil {
		return BackupResult{}, err
	}
	skipped, err := b.home(ctx, ht, req.Username, uid, gid, home)
	if err != nil {
		return BackupResult{}, fmt.Errorf("back up the home folder: %w", err)
	}
	for _, db := range req.Databases {
		if err := b.dump(ctx, ht, dir, db, now); err != nil {
			return BackupResult{}, fmt.Errorf("dump database %s: %w", db, err)
		}
	}
	m, err := json.MarshalIndent(BackupManifest{Format: BackupFormat, Panel: b.Version, Username: req.Username, Created: now, Entries: ht.sums}, "", "  ")
	if err != nil {
		return BackupResult{}, err
	}
	if err := ht.file("manifest.json", 0o600, now, int64(len(m)), strings.NewReader(string(m))); err != nil {
		return BackupResult{}, err
	}
	if err := ht.tw.Close(); err != nil {
		return BackupResult{}, err
	}
	if err := zw.Close(); err != nil {
		return BackupResult{}, err
	}
	if err := f.Sync(); err != nil {
		return BackupResult{}, err
	}
	return BackupResult{Size: counted.n, SHA256: hex.EncodeToString(sum.Sum(nil)), Skipped: skipped}, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// home streams the home folder from tar run as the account's user and
// re-packs every entry under homedir/.
func (b *Backups) home(ctx context.Context, ht *hashingTar, username string, uid, gid int, home string) ([]string, error) {
	pr, pw := io.Pipe()
	type result struct {
		res execx.Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := b.Run.Run(ctx, execx.Cmd{
			Path: SystemdRunPath, Timeout: backupMaxRuntime, Stdout: pw, MaxOutput: 256 << 10,
			Args: []string{
				"--wait", "--pipe", "--quiet", "--collect", "--service-type=exec",
				"--unit=xcp-backup-" + username + ".service", "--slice=" + SliceName(username),
				"--uid=" + strconv.Itoa(uid), "--gid=" + strconv.Itoa(gid), "--working-directory=" + home,
				"--property=RuntimeMaxSec=" + strconv.Itoa(int(backupMaxRuntime.Seconds())),
				"--", "/usr/bin/tar", "--create", "--file=-", "--format=pax", "--one-file-system",
				"--ignore-failed-read", "--warning=no-file-changed", "--warning=no-file-removed", ".",
			},
		})
		pw.CloseWithError(err) // nil: EOF for the reader
		done <- result{res, err}
	}()
	copyErr := repackHome(ht, bufio.NewReaderSize(pr, 1<<20))
	if copyErr != nil {
		pr.CloseWithError(copyErr) // stops tar
	}
	_, _ = io.Copy(io.Discard, pr)
	r := <-done
	if copyErr != nil {
		return nil, copyErr
	}
	if r.err != nil {
		return nil, fmt.Errorf("%w: %s", r.err, strings.TrimSpace(string(r.res.Stderr)))
	}
	var skipped []string
	for _, l := range strings.Split(string(r.res.Stderr), "\n") {
		if strings.Contains(l, "Cannot") && len(skipped) < backupMaxSkipped {
			skipped = append(skipped, strings.TrimPrefix(l, "/usr/bin/tar: "))
		}
	}
	return skipped, nil
}

// repackHome copies the entries of a tar stream of the home folder into
// the backup under homedir/, with the SHA-256 of every file.
func repackHome(ht *hashingTar, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		hdr.Name = "homedir/" + rel
		if rel == "" {
			hdr.Name = "homedir/"
		}
		hdr.Format = tar.FormatPAX
		if err := ht.tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		sum := sha256.New()
		if _, err := io.Copy(ht.tw, io.TeeReader(tr, sum)); err != nil {
			return err
		}
		ht.sums[hdr.Name] = hex.EncodeToString(sum.Sum(nil))
	}
}

// dump adds one database's dump, made in a root-only staging file first
// (a tar entry needs its size up front).
func (b *Backups) dump(ctx context.Context, ht *hashingTar, dir *fsx.Root, db string, now time.Time) error {
	tmp, err := dir.OpenFile(backupStagingName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		_ = dir.Remove(backupStagingName)
	}()
	res, err := b.Run.Run(ctx, execx.Cmd{
		Path: MariaDBDumpPath, Timeout: backupMaxRuntime, Stdout: tmp,
		Args: []string{"--single-transaction", "--routines", "--triggers", "--events", "--hex-blob", "--databases", "--", db},
	})
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res.Stderr)))
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return ht.file("mysql/"+db+".sql", 0o600, now, size, tmp)
}

// Delete removes one backup of an account.
func (b *Backups) Delete(username, file string) (bool, error) {
	if validate.Username(username) != nil {
		return false, invalid("%q is not an account name", username)
	}
	if err := CheckBackupFile(username, file); err != nil {
		return false, err
	}
	dir, err := fsx.OpenRoot(filepath.Join(b.Dir, username))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	err = dir.Remove(file)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Read returns up to length bytes of a backup from offset, and its size.
func (b *Backups) Read(username, file string, offset, length int64) ([]byte, int64, error) {
	if validate.Username(username) != nil {
		return nil, 0, invalid("%q is not an account name", username)
	}
	if err := CheckBackupFile(username, file); err != nil {
		return nil, 0, err
	}
	if offset < 0 || length < 1 || length > BackupMaxRead {
		return nil, 0, invalid("offset and length: a part of at most %d bytes", BackupMaxRead)
	}
	dir, err := fsx.OpenRoot(filepath.Join(b.Dir, username))
	if err != nil {
		return nil, 0, err
	}
	defer dir.Close()
	f, err := dir.Open(file)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, min(length, max(fi.Size()-offset, 0)))
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	return buf[:n], fi.Size(), nil
}

// RemoveAccount removes all backups of an account (when it is terminated).
func (b *Backups) RemoveAccount(username string) (bool, error) {
	if validate.Username(username) != nil {
		return false, invalid("%q is not an account name", username)
	}
	p := filepath.Join(b.Dir, username)
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return true, os.RemoveAll(p) // the folder is root's: no one else's links can be inside
}
