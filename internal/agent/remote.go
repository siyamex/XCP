package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/validate"
)

// Remote backup destinations (ADR-0031): where copies of the account backups
// are kept off the server. The panel keeps the settings and the secrets and
// passes them with each call; the agent keeps nothing.

// Kinds of destination.
const (
	RemoteFolder = "folder" // a folder on this server, like a mounted disk
	RemoteSFTP   = "sftp"
	RemoteS3     = "s3"
)

// RemoteSpec says where and how to reach a destination.
type RemoteSpec struct {
	Kind string

	// folder, sftp: the base folder (sftp: on the server, absolute or relative to its home).
	// s3: the key prefix. Backups go to <Path>/<account>/<file>.
	Path string

	// sftp
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey string // PEM; used instead of the password when set
	HostKey    string // SHA256:... fingerprint of the server's key; empty only for RemoteTest, which then reports it

	// s3
	Endpoint  string // host[:port]; empty: Amazon S3
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseTLS    bool
}

// RemoteObject is a file at a destination.
type RemoteObject struct {
	Account string
	File    string
	Size    int64
	Time    time.Time
}

// RemoteTestResult is what a connection test found.
type RemoteTestResult struct {
	HostKey string // sftp: the fingerprint the server presented
}

// remoteStore is the little a destination has to do.
type remoteStore interface {
	// Put stores r as key (account/file) and returns when it is complete.
	Put(ctx context.Context, account, file string, r io.Reader, size int64) error
	// Get opens a stored file.
	Get(ctx context.Context, account, file string) (io.ReadCloser, error)
	// List returns the backups of one account, or of every account when account is "".
	List(ctx context.Context, account string) ([]RemoteObject, error)
	Delete(ctx context.Context, account, file string) error
	// Check proves the destination can be reached and written to.
	Check(ctx context.Context) error
	Close() error
}

var (
	sshUserRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	hostKeyRe   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	bucketRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRe    = regexp.MustCompile(`^[a-z0-9-]{2,30}$`)
	accessKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/=._-]{3,128}$`)
	remotePath  = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
)

func cleanRemotePath(p string) (string, bool) {
	if !remotePath.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return "", false
	}
	c := path.Clean("/" + p)[1:]
	if strings.HasPrefix(p, "/") {
		c = path.Clean(p)
	}
	return c, true
}

// CheckRemote validates a destination. Secrets are checked for shape only.
func CheckRemote(s RemoteSpec) error {
	switch s.Kind {
	case RemoteFolder:
		if !strings.HasPrefix(s.Path, "/") {
			return invalid("the folder must be an absolute path")
		}
		c, ok := cleanRemotePath(s.Path)
		if !ok || c != s.Path || c == "/" || strings.Count(c, "/") < 1 {
			return invalid("%q is not a clean folder like /mnt/backup", s.Path)
		}
		for _, bad := range []string{"/proc", "/sys", "/dev", "/run", "/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/root"} {
			if c == bad || strings.HasPrefix(c, bad+"/") {
				return invalid("%s cannot be a backup destination", bad)
			}
		}
	case RemoteSFTP:
		if _, err := validate.IP(s.Host); err != nil {
			if d, derr := validate.Domain(s.Host); derr != nil || d != s.Host {
				return invalid("the SFTP server %q is not a host name or an IP address", s.Host)
			}
		}
		if s.Port < 1 || s.Port > 65535 {
			return invalid("the SFTP port is 1 to 65535")
		}
		if !sshUserRe.MatchString(s.User) {
			return invalid("the SFTP user name %q is not valid", s.User)
		}
		if c, ok := cleanRemotePath(s.Path); !ok || c != strings.TrimSuffix(s.Path, "/") && s.Path != "" {
			return invalid("the SFTP folder %q is not a clean path", s.Path)
		}
		if s.Password == "" && s.PrivateKey == "" {
			return invalid("an SFTP password or private key is needed")
		}
		if len(s.Password) > 1024 || len(s.PrivateKey) > 16384 {
			return invalid("the SFTP password or key is too long")
		}
		if s.HostKey != "" && !hostKeyRe.MatchString(s.HostKey) {
			return invalid("the host key is a fingerprint like SHA256:...")
		}
	case RemoteS3:
		if s.Endpoint != "" {
			host, port, err := net.SplitHostPort(s.Endpoint)
			if err != nil {
				host, port = s.Endpoint, ""
			}
			if _, ierr := validate.IP(host); ierr != nil {
				if d, derr := validate.Domain(host); derr != nil || d != host {
					return invalid("the S3 endpoint %q is not host or host:port", s.Endpoint)
				}
			}
			if port != "" {
				if p, ok := atoiPort(port); !ok || p < 1 {
					return invalid("the S3 endpoint port is not valid")
				}
			}
		}
		if !bucketRe.MatchString(s.Bucket) {
			return invalid("the bucket name %q is not valid", s.Bucket)
		}
		if s.Region != "" && !regionRe.MatchString(s.Region) {
			return invalid("the region %q is not valid", s.Region)
		}
		if c, ok := cleanRemotePath(s.Path); !ok || c != strings.Trim(s.Path, "/") && s.Path != "" {
			return invalid("the S3 prefix %q is not a clean path", s.Path)
		}
		if !accessKeyRe.MatchString(s.AccessKey) {
			return invalid("the S3 access key is not valid")
		}
		if s.SecretKey == "" || len(s.SecretKey) > 256 {
			return invalid("an S3 secret key is needed")
		}
	default:
		return invalid("destination kind %q: folder, sftp or s3", s.Kind)
	}
	return nil
}

func atoiPort(s string) (int, bool) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' || n > 65535 {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n >= 1 && n <= 65535
}

// Remote copies backups to destinations.
type Remote struct {
	Backups *Backups
	// Open is the destination factory; nil uses the real one. Tests replace it.
	Open func(ctx context.Context, s RemoteSpec) (remoteStore, error)
}

func (r *Remote) open(ctx context.Context, s RemoteSpec) (remoteStore, error) {
	if err := CheckRemote(s); err != nil {
		return nil, err
	}
	if r.Open != nil {
		return r.Open(ctx, s)
	}
	switch s.Kind {
	case RemoteFolder:
		return openFolder(s)
	case RemoteSFTP:
		return openSFTP(ctx, s)
	default:
		return openS3(s)
	}
}

func checkAccountFile(account, file string) error {
	if validate.Username(account) != nil {
		return invalid("%q is not an account name", account)
	}
	return CheckBackupFile(account, file)
}

// Test connects, writes and removes a small file, and reports the SFTP
// host key. With an SFTP spec that has no HostKey it only connects to learn it.
func (r *Remote) Test(ctx context.Context, s RemoteSpec) (RemoteTestResult, error) {
	if s.Kind == RemoteSFTP && s.HostKey == "" {
		if err := CheckRemote(s); err != nil {
			return RemoteTestResult{}, err
		}
		fp, err := sftpHostKey(ctx, s)
		return RemoteTestResult{HostKey: fp}, err
	}
	st, err := r.open(ctx, s)
	if err != nil {
		return RemoteTestResult{}, err
	}
	defer st.Close()
	if err := st.Check(ctx); err != nil {
		return RemoteTestResult{}, err
	}
	return RemoteTestResult{HostKey: s.HostKey}, nil
}

// Upload copies a local backup to the destination and checks the size there.
func (r *Remote) Upload(ctx context.Context, s RemoteSpec, account, file string) (int64, error) {
	if err := checkAccountFile(account, file); err != nil {
		return 0, err
	}
	f, size, err := r.Backups.openLocal(account, file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := r.open(ctx, s)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := st.Put(ctx, account, file, f, size); err != nil {
		return 0, fmt.Errorf("upload: %w", err)
	}
	// Prove it arrived whole.
	objs, err := st.List(ctx, account)
	if err != nil {
		return 0, fmt.Errorf("check the upload: %w", err)
	}
	for _, o := range objs {
		if o.File == file {
			if o.Size != size {
				_ = st.Delete(ctx, account, file)
				return 0, fmt.Errorf("the copy has %d bytes, the backup %d", o.Size, size)
			}
			return size, nil
		}
	}
	return 0, errors.New("the copy is not at the destination after the upload")
}

// List returns the backups at the destination.
func (r *Remote) List(ctx context.Context, s RemoteSpec, account string) ([]RemoteObject, error) {
	if account != "" && validate.Username(account) != nil {
		return nil, invalid("%q is not an account name", account)
	}
	st, err := r.open(ctx, s)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	return st.List(ctx, account)
}

// Delete removes a backup from the destination.
func (r *Remote) Delete(ctx context.Context, s RemoteSpec, account, file string) error {
	if err := checkAccountFile(account, file); err != nil {
		return err
	}
	st, err := r.open(ctx, s)
	if err != nil {
		return err
	}
	defer st.Close()
	return st.Delete(ctx, account, file)
}

// Fetch copies a backup from the destination into the server's own backup
// folder of the account (never over an existing file).
func (r *Remote) Fetch(ctx context.Context, s RemoteSpec, account, file string) (int64, error) {
	if err := checkAccountFile(account, file); err != nil {
		return 0, err
	}
	st, err := r.open(ctx, s)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	rc, err := st.Get(ctx, account, file)
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer rc.Close()
	return r.Backups.importLocal(account, file, rc)
}
