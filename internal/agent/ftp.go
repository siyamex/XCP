package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/pwhash"
	"github.com/siyamex/XCP/internal/validate"
)

// FTP runs the FTP logins of all accounts with Pure-FTPd and xcp-ftpauth
// (ADR-0010). Each account's logins are kept as a fragment, which
// xcp-ftpauth reads when Pure-FTPd asks it to check a login.
type FTP struct {
	Binary      string // /usr/sbin/pure-ftpd; missing means FTP is not installed
	FragmentDir string // /etc/xcp/ftp/accounts, root only
	ConfFile    string // /etc/pure-ftpd/xcp.conf
	HomesRoot   string // /home
	HostCert    *HostCert
	PanelCert   string // the self-signed pair, until the host name has a certificate
	PanelKey    string
	Services    ServiceManager
	Run         *execx.Runner // runs pure-ftpwho; nil in tests
	kill        func(pid int) error
	mu          sync.Mutex
}

// Paths of the Ubuntu setup made by xcp-install.
const (
	FTPBinary      = "/usr/sbin/pure-ftpd"
	FTPFragmentDir = "/etc/xcp/ftp/accounts"
	FTPConfFile    = "/etc/pure-ftpd/xcp.conf"
	FTPAuthSocket  = "/run/xcp-ftpauth/auth.sock"
	FTPXferLog     = "/var/log/pure-ftpd/xferlog"
	FTPMaxLogins   = 1000 // per account
	FTPPassiveMin  = 30000
	FTPPassiveMax  = 30999
	ftpUnit        = "pure-ftpd.service"
)

// FTPAccount is all FTP logins of one account, as the fragment xcp-ftpauth
// reads. UID, GID and Home are the agent's own findings, never the request's.
type FTPAccount struct {
	Username string
	UID, GID int
	Home     string // absolute
	Logins   []FTPLogin
}

// FTPLogin is one FTP login.
type FTPLogin struct {
	Login        string // name@domain, lower case
	PasswordHash string // {ARGON2ID}$argon2id$...
	Dir          string // folder relative to the home; "." is the home
	QuotaMB      int64  // 0: no quota of its own
}

var ftpNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,30}[a-z0-9])?$`)

// CheckFTPLogin checks a login name: name@domain, normalised.
func CheckFTPLogin(s string) error {
	name, domain, ok := strings.Cut(s, "@")
	if !ok || !ftpNameRe.MatchString(name) || strings.Contains(name, "..") {
		return invalid("FTP login %q: the name before @ is 1 to 32 lower-case letters, digits, dots, dashes or underscores", s)
	}
	if d, err := validate.Domain(domain); err != nil || d != domain || strings.HasPrefix(domain, "*.") {
		return invalid("FTP login %q: %q is not a normalised domain name", s, domain)
	}
	return nil
}

// CheckFTPAccount checks an account's logins.
func CheckFTPAccount(a FTPAccount) error {
	if validate.Username(a.Username) != nil {
		return invalid("%q is not an account name", a.Username)
	}
	if len(a.Logins) > FTPMaxLogins {
		return invalid("at most %d FTP logins per account", FTPMaxLogins)
	}
	seen := map[string]bool{}
	for _, l := range a.Logins {
		if err := CheckFTPLogin(l.Login); err != nil {
			return err
		}
		if seen[l.Login] {
			return invalid("FTP login %s is listed twice", l.Login)
		}
		seen[l.Login] = true
		if !pwhash.Valid(l.PasswordHash) {
			return invalid("FTP login %s: the password hash is not %s", l.Login, pwhash.Prefix)
		}
		if c, err := fsx.CleanRel(l.Dir); err != nil || c != l.Dir {
			return invalid("FTP login %s: folder %q is not a clean path inside the home", l.Login, l.Dir)
		}
		if l.QuotaMB < 0 || l.QuotaMB > 1<<33 {
			return invalid("FTP login %s: quota out of range", l.Login)
		}
	}
	return nil
}

func (f *FTP) installed() error {
	if _, err := os.Stat(f.Binary); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the FTP server is not installed: %w", ErrNotInstalled)
	}
	return nil
}

// ReadFTPFragments reads all accounts' fragments from dir.
func ReadFTPFragments(dir string) ([]FTPAccount, error) {
	root, err := fsx.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	ents, err := root.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []FTPAccount
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") || !e.Type().IsRegular() {
			continue
		}
		b, err := root.ReadFile(e.Name(), 16<<20)
		if err != nil {
			return nil, err
		}
		var a FTPAccount
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("FTP fragment %s: %w", e.Name(), err)
		}
		out = append(out, a)
	}
	return out, nil
}

// ApplyAccount stores an account's FTP logins, after making their folders.
// It refuses a login another account has. It reports whether anything
// changed, and the logins whose folder could not be made: those are stored
// too (xcp-ftpauth refuses them until the folder is usable), so one bad
// folder does not hold up the account's other changes.
func (f *FTP) ApplyAccount(_ context.Context, a FTPAccount) (changed bool, problems []string, err error) {
	if validate.Username(a.Username) != nil {
		return false, nil, invalid("%q is not an account name", a.Username)
	}
	u, err := lookup(a.Username)
	if err != nil {
		return false, nil, err
	}
	if u == nil || u.Name != AccountMarker {
		return false, nil, ErrNotOurUser
	}
	a.UID, _ = strconv.Atoi(u.Uid)
	a.GID, _ = strconv.Atoi(u.Gid)
	a.Home = filepath.Join(f.HomesRoot, a.Username)
	if err := CheckFTPAccount(a); err != nil {
		return false, nil, err
	}
	if err := f.installed(); err != nil {
		return false, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := ReadFTPFragments(f.FragmentDir)
	if err != nil {
		return false, nil, err
	}
	owner := map[string]string{}
	for _, o := range all {
		for _, l := range o.Logins {
			owner[l.Login] = o.Username
		}
	}
	for _, l := range a.Logins {
		if o := owner[l.Login]; o != "" && o != a.Username {
			return false, nil, invalid("FTP login %s belongs to account %s", l.Login, o)
		}
	}
	root, err := fsx.OpenRoot(a.Home)
	if err != nil {
		return false, nil, err
	}
	for _, l := range a.Logins {
		if err := folder(root, l.Dir, a.UID, a.GID); err != nil {
			problems = append(problems, fmt.Sprintf("FTP login %s: folder %s: %v", l.Login, l.Dir, err))
		}
	}
	root.Close()
	b, err := json.Marshal(a)
	if err != nil {
		return false, problems, err
	}
	changed, err = writeFile(f.FragmentDir, a.Username+".json", string(b), 0o600, "")
	return changed, problems, err
}

// folder makes a login's missing folder, owned by the account's user.
// Nothing on the way may be a symlink (fsx), and an existing part must be a
// folder.
func folder(root *fsx.Root, dir string, uid, gid int) error {
	if dir == "." {
		return nil
	}
	p := ""
	for _, elem := range strings.Split(dir, "/") {
		p = path.Join(p, elem)
		fi, err := root.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := root.Mkdir(p, 0o755); err != nil {
				return err
			}
			if err := root.Chown(p, uid, gid); err != nil {
				return err
			}
		case err != nil:
			return err
		case !fi.IsDir():
			return fmt.Errorf("%s is not a folder", p)
		}
	}
	return nil
}

// RemoveAccount drops an account's FTP logins. Its files stay.
func (f *FTP) RemoveAccount(_ context.Context, username string) (bool, error) {
	if validate.Username(username) != nil {
		return false, invalid("%q is not an account name", username)
	}
	if err := f.installed(); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	root, err := fsx.OpenRoot(f.FragmentDir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	err = root.Remove(username + ".json")
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// tls returns the certificate FTPS serves: the host name's once AutoSSL
// installed it, the panel's self-signed one before.
func (f *FTP) tls() (cert, key string) {
	if f.HostCert != nil {
		if _, err := os.Stat(f.HostCert.CertFile); err == nil {
			return f.HostCert.CertFile, f.HostCert.KeyFile
		}
	}
	return f.PanelCert, f.PanelKey
}

// RefreshTLS renders Pure-FTPd's configuration with the current
// certificate and restarts it if the file changed.
func (f *FTP) RefreshTLS(ctx context.Context) (bool, error) {
	if f.installed() != nil {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cert, key := f.tls()
	changed, err := writeFile(filepath.Dir(f.ConfFile), filepath.Base(f.ConfFile), FTPConfig(cert, key), 0o644, "")
	if err != nil || !changed {
		return changed, err
	}
	return true, f.Services.Do(ctx, ftpUnit, ActionRestart)
}

// FTPConfig renders Pure-FTPd's configuration (ADR-0010); xcp-install
// writes the same file.
func FTPConfig(cert, key string) string {
	return fmt.Sprintf(`# Managed by XCP (ADR-0010). Changes are overwritten.
# Logins are checked by xcp-ftpauth; every login is locked into its folder.
ExtAuth %s
ChrootEveryone yes
NoAnonymous yes
AnonymousCantUpload yes
AnonymousCanCreateDirs no
MinUID 10000
BrokenClientsCompatibility no
MaxClientsNumber 200
MaxClientsPerIP 20
MaxIdleTime 15
LimitRecursion 10000 8
DisplayDotFiles yes
DontResolve yes
CustomerProof yes
AllowUserFXP no
AllowAnonymousFXP no
AutoRename no
CreateHomeDir no
KeepAllFiles no
Umask 133:022
MaxDiskUsage 99
PassivePortRange %d %d
SyslogFacility ftp
VerboseLog no
AltLog xferlog:%s
PIDFile /run/pure-ftpd.pid
# Explicit FTPS, optional for now (USR-FTP-03 adds a switch to require it).
TLS 1
TLSCipherSuite HIGH:!aNULL:!MD5:!RC4
CertFileAndKey "%s" "%s"
`, FTPAuthSocket, FTPPassiveMin, FTPPassiveMax, FTPXferLog, cert, key)
}
