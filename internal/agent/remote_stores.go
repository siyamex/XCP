package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/siyamex/XCP/internal/fsx"
)

// ---- the server's own backup folder ----

// openLocal opens a local backup for reading.
func (b *Backups) openLocal(account, file string) (*os.File, int64, error) {
	dir, err := fsx.OpenRoot(filepath.Join(b.Dir, account))
	if err != nil {
		return nil, 0, err
	}
	defer dir.Close()
	f, err := dir.Open(file)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("%s is not a file", file)
	}
	return f, fi.Size(), nil
}

// importLocal stores a downloaded backup in the account's backup folder
// without replacing a backup that is there.
func (b *Backups) importLocal(account, file string, r io.Reader) (int64, error) {
	dir, err := b.accountDir(account)
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	if _, err := dir.Lstat(file); err == nil {
		return 0, fmt.Errorf("%s is already on this server", file)
	}
	part := file + backupPartSuffix
	f, err := dir.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = dir.Remove(part)
		return 0, err
	}
	if err := dir.Rename(part, file); err != nil {
		_ = dir.Remove(part)
		return 0, err
	}
	return n, nil
}

// ---- folder ----

type folderStore struct{ base string }

func openFolder(s RemoteSpec) (remoteStore, error) {
	if st, err := os.Stat(s.Path); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder on this server", s.Path)
	}
	return &folderStore{base: s.Path}, nil
}

func (f *folderStore) account(account string) (*fsx.Root, error) {
	root, err := fsx.OpenRoot(f.base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.Mkdir(account, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return fsx.OpenRoot(filepath.Join(f.base, account))
}

func (f *folderStore) Put(_ context.Context, account, file string, r io.Reader, _ int64) error {
	dir, err := f.account(account)
	if err != nil {
		return err
	}
	defer dir.Close()
	part := file + backupPartSuffix
	w, err := dir.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = dir.Remove(part)
		return err
	}
	return dir.Rename(part, file)
}

func (f *folderStore) Get(_ context.Context, account, file string) (io.ReadCloser, error) {
	dir, err := fsx.OpenRoot(filepath.Join(f.base, account))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Open(file)
}

func (f *folderStore) List(_ context.Context, account string) ([]RemoteObject, error) {
	var accounts []string
	if account != "" {
		accounts = []string{account}
	} else {
		ents, err := os.ReadDir(f.base)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if e.IsDir() {
				accounts = append(accounts, e.Name())
			}
		}
	}
	var out []RemoteObject
	for _, a := range accounts {
		ents, err := os.ReadDir(filepath.Join(f.base, a))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if !e.Type().IsRegular() || !backupFileRe.MatchString(e.Name()) {
				continue
			}
			if fi, err := e.Info(); err == nil {
				out = append(out, RemoteObject{Account: a, File: e.Name(), Size: fi.Size(), Time: fi.ModTime()})
			}
		}
	}
	sortObjects(out)
	return out, nil
}

func (f *folderStore) Delete(_ context.Context, account, file string) error {
	dir, err := fsx.OpenRoot(filepath.Join(f.base, account))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (f *folderStore) Check(_ context.Context) error {
	name := ".xcp-check-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	root, err := fsx.OpenRoot(f.base)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteFileAtomic(name, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("the folder cannot be written to: %w", err)
	}
	return root.Remove(name)
}

func (f *folderStore) Close() error { return nil }

func sortObjects(o []RemoteObject) {
	sort.Slice(o, func(i, j int) bool {
		if o[i].Account != o[j].Account {
			return o[i].Account < o[j].Account
		}
		return o[i].File < o[j].File
	})
}

// ---- SFTP ----

type sftpStore struct {
	ssh  *ssh.Client
	sftp *sftp.Client
	base string
}

func sshConfig(s RemoteSpec, verify ssh.HostKeyCallback) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if s.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(s.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("the private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		auth = append(auth, ssh.Password(s.Password))
	}
	return &ssh.ClientConfig{User: s.User, Auth: auth, HostKeyCallback: verify, Timeout: 20 * time.Second}, nil
}

func fingerprint(k ssh.PublicKey) string {
	h := sha256.Sum256(k.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(h[:]), "=")
}

func dialSSH(ctx context.Context, s RemoteSpec, verify ssh.HostKeyCallback) (*ssh.Client, error) {
	cfg, err := sshConfig(s, verify)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// sftpHostKey connects once, only to learn the server's key fingerprint.
func sftpHostKey(ctx context.Context, s RemoteSpec) (string, error) {
	var fp string
	cfg, err := sshConfig(s, func(_ string, _ net.Addr, k ssh.PublicKey) error {
		fp = fingerprint(k)
		return nil
	})
	if err != nil {
		return "", err
	}
	// The key arrives before the login: stop after it, whatever the login says.
	cfg.Auth = []ssh.AuthMethod{ssh.Password(s.Password + "x")}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c, _, _, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), cfg)
	if err == nil {
		c.Close()
	}
	if fp == "" {
		return "", fmt.Errorf("no host key: %w", err)
	}
	return fp, nil
}

func openSFTP(ctx context.Context, s RemoteSpec) (remoteStore, error) {
	c, err := dialSSH(ctx, s, func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if fp := fingerprint(k); fp != s.HostKey {
			return fmt.Errorf("the server's host key is %s, not the %s that was trusted: someone may be between you and the server, or it was reinstalled", fp, s.HostKey)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	cl, err := sftp.NewClient(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &sftpStore{ssh: c, sftp: cl, base: strings.TrimSuffix(s.Path, "/")}, nil
}

func (s *sftpStore) dir(account string) string {
	if s.base == "" {
		return account
	}
	return path.Join(s.base, account)
}

func (s *sftpStore) Put(_ context.Context, account, file string, r io.Reader, _ int64) error {
	d := s.dir(account)
	if err := s.sftp.MkdirAll(d); err != nil {
		return err
	}
	part := path.Join(d, file+backupPartSuffix)
	w, err := s.sftp.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = s.sftp.Remove(part)
		return err
	}
	final := path.Join(d, file)
	_ = s.sftp.Remove(final) // PosixRename is not on every server
	if err := s.sftp.Rename(part, final); err != nil {
		_ = s.sftp.Remove(part)
		return err
	}
	return nil
}

func (s *sftpStore) Get(_ context.Context, account, file string) (io.ReadCloser, error) {
	return s.sftp.Open(path.Join(s.dir(account), file))
}

func (s *sftpStore) List(_ context.Context, account string) ([]RemoteObject, error) {
	var accounts []string
	if account != "" {
		accounts = []string{account}
	} else {
		root := s.base
		if root == "" {
			root = "."
		}
		ents, err := s.sftp.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if e.IsDir() {
				accounts = append(accounts, e.Name())
			}
		}
	}
	var out []RemoteObject
	for _, a := range accounts {
		ents, err := s.sftp.ReadDir(s.dir(a))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if e.Mode().IsRegular() && backupFileRe.MatchString(e.Name()) {
				out = append(out, RemoteObject{Account: a, File: e.Name(), Size: e.Size(), Time: e.ModTime()})
			}
		}
	}
	sortObjects(out)
	return out, nil
}

func (s *sftpStore) Delete(_ context.Context, account, file string) error {
	if err := s.sftp.Remove(path.Join(s.dir(account), file)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s *sftpStore) Check(context.Context) error {
	d := s.dir(".xcp-check")
	if err := s.sftp.MkdirAll(d); err != nil {
		return fmt.Errorf("the folder cannot be written to: %w", err)
	}
	return s.sftp.RemoveDirectory(d)
}

func (s *sftpStore) Close() error {
	_ = s.sftp.Close()
	return s.ssh.Close()
}

// ---- S3 ----

type s3Store struct {
	c      *minio.Client
	bucket string
	prefix string
}

func openS3(s RemoteSpec) (remoteStore, error) {
	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}
	c, err := minio.New(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(s.AccessKey, s.SecretKey, ""), Secure: s.UseTLS || s.Endpoint == "",
		Region: s.Region, BucketLookup: minio.BucketLookupAuto,
	})
	if err != nil {
		return nil, err
	}
	return &s3Store{c: c, bucket: s.Bucket, prefix: strings.Trim(s.Path, "/")}, nil
}

func (s *s3Store) key(account, file string) string {
	k := account + "/" + file
	if s.prefix != "" {
		k = s.prefix + "/" + k
	}
	return k
}

func (s *s3Store) Put(ctx context.Context, account, file string, r io.Reader, size int64) error {
	_, err := s.c.PutObject(ctx, s.bucket, s.key(account, file), r, size, minio.PutObjectOptions{ContentType: "application/zstd"})
	return err
}

func (s *s3Store) Get(ctx context.Context, account, file string) (io.ReadCloser, error) {
	o, err := s.c.GetObject(ctx, s.bucket, s.key(account, file), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := o.Stat(); err != nil {
		o.Close()
		return nil, err
	}
	return o, nil
}

func (s *s3Store) List(ctx context.Context, account string) ([]RemoteObject, error) {
	prefix := s.prefix
	if prefix != "" {
		prefix += "/"
	}
	if account != "" {
		prefix += account + "/"
	}
	var out []RemoteObject
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		rest := strings.TrimPrefix(o.Key, prefix)
		acct, file := account, rest
		if account == "" {
			var ok bool
			if acct, file, ok = strings.Cut(rest, "/"); !ok {
				continue
			}
		}
		if backupFileRe.MatchString(file) && !strings.Contains(file, "/") {
			out = append(out, RemoteObject{Account: acct, File: file, Size: o.Size, Time: o.LastModified})
		}
	}
	sortObjects(out)
	return out, nil
}

func (s *s3Store) Delete(ctx context.Context, account, file string) error {
	return s.c.RemoveObject(ctx, s.bucket, s.key(account, file), minio.RemoveObjectOptions{})
}

func (s *s3Store) Check(ctx context.Context) error {
	ok, err := s.c.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the bucket %s does not exist or is not visible to this key", s.bucket)
	}
	name := s.key(".xcp-check", "x-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if _, err := s.c.PutObject(ctx, s.bucket, name, strings.NewReader("ok"), 2, minio.PutObjectOptions{}); err != nil {
		return fmt.Errorf("the bucket cannot be written to: %w", err)
	}
	return s.c.RemoveObject(ctx, s.bucket, name, minio.RemoveObjectOptions{})
}

func (s *s3Store) Close() error { return nil }
