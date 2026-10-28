// Package install turns a fresh server into an XCP server (P0 task 10).
// Every step is idempotent: re-running the installer upgrades binaries and
// unit files, keeps the existing config, key, certificate and database, and
// only restarts services when something changed.
package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/siyamex/XCP/internal/secretbox"
)

//go:embed units/*.service
var units embed.FS

// ServiceUser is the account xcp-api and xcp-worker run as.
const ServiceUser = "xcp"

// Binaries copied from Options.BinDir, with their install paths.
var Binaries = map[string]string{
	"xcp-agent": "/usr/sbin/xcp-agent",
	"xcp-api":   "/usr/sbin/xcp-api",
	"xcpctl":    "/usr/bin/xcpctl",
}

// Well-known paths (without Options.Root).
const (
	ConfigFile = "/etc/xcp/xcp.toml"
	SecretsDir = "/etc/xcp/secrets" //nolint:gosec // G101: a directory path, not a credential
	SSLDir     = "/etc/xcp/ssl"
	CertFile   = SSLDir + "/panel.crt"
	KeyFile    = SSLDir + "/panel.key"
	StateDir   = "/var/lib/xcp"
	UnitDir    = "/etc/systemd/system"
	PanelPort  = 2443
)

// System performs the changes that are not plain file writes.
type System interface {
	EnsureSystemUser(ctx context.Context, name, home string) (created bool, err error)
	LookupIDs(name string) (uid, gid int, err error)
	Chown(path string, uid, gid int) error
	Systemctl(ctx context.Context, args ...string) error
	// CreateFirstAdmin runs `xcpctl admin create --if-none`; it reports whether a login was created.
	CreateFirstAdmin(ctx context.Context, username, password string, mustChange bool) (created bool, err error)
	WaitHealthy(ctx context.Context, url string, caPEM []byte) error
	// InstallWebStack installs Apache and PHP-FPM and enables the Apache
	// modules XCP needs. It reports whether anything was installed.
	InstallWebStack(ctx context.Context) (installed bool, err error)
	// EnableApacheConf enables conf-available/xcp.conf and reloads Apache.
	EnableApacheConf(ctx context.Context) error
}

// Options configure an install.
type Options struct {
	Root          string   // filesystem prefix: "/" on a server, a temp dir in tests
	BinDir        string   // directory holding xcp-agent, xcp-api and xcpctl
	Hostname      string   // for the panel URL and certificate
	IPs           []string // extra IPs for the certificate (the server's addresses)
	AdminUser     string
	AdminPassword string // empty: generate one and print it once
	NoWeb         bool   // skip installing Apache and PHP-FPM
	DryRun        bool
	Out           io.Writer
	Sys           System
}

// Result summarises what the installer did.
type Result struct {
	URL               string
	AdminCreated      bool
	GeneratedPassword string
	Changed           []string
}

type installer struct {
	o       Options
	res     Result
	uid     int // service user, -1 in dry runs before it exists
	gid     int
	restart bool // binaries or units changed: restart services
	reload  bool // units changed: daemon-reload
}

// Run performs the installation.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	in := &installer{o: o, uid: -1, gid: -1}
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"service user", in.user},
		{"directories", in.dirs},
		{"binaries", in.binaries},
		{"config", in.config},
		{"master key", in.masterKey},
		{"TLS certificate", in.certificate},
		{"systemd units", in.units},
		{"web server (Apache + PHP-FPM)", in.web},
		{"services", in.services},
		{"first admin", in.admin},
	}
	for _, s := range steps {
		in.logf("==> %s", s.name)
		if err := s.fn(ctx); err != nil {
			return &in.res, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	in.res.URL = fmt.Sprintf("https://%s:%d", o.Hostname, PanelPort)
	return &in.res, nil
}

func (in *installer) logf(format string, args ...any) {
	fmt.Fprintf(in.o.Out, format+"\n", args...)
}

// path maps an absolute server path into Options.Root.
func (in *installer) path(p string) string {
	return filepath.Join(in.o.Root, filepath.FromSlash(p))
}

func (in *installer) changed(what string) {
	in.res.Changed = append(in.res.Changed, what)
	if in.o.DryRun {
		in.logf("    would change: %s", what)
	} else {
		in.logf("    changed: %s", what)
	}
}

func (in *installer) user(ctx context.Context) error {
	if in.o.DryRun {
		if uid, gid, err := in.o.Sys.LookupIDs(ServiceUser); err == nil {
			in.uid, in.gid = uid, gid
		} else {
			in.changed("create system user " + ServiceUser)
		}
		return nil
	}
	created, err := in.o.Sys.EnsureSystemUser(ctx, ServiceUser, StateDir)
	if err != nil {
		return err
	}
	if created {
		in.changed("created system user " + ServiceUser)
	}
	in.uid, in.gid, err = in.o.Sys.LookupIDs(ServiceUser)
	return err
}

type owner int

const (
	rootRoot owner = iota // root:root
	rootSvc               // root:xcp (service can read)
	svcSvc                // xcp:xcp (service owns)
)

func (in *installer) chown(p string, o owner) error {
	if in.o.DryRun || o == rootRoot && os.Geteuid() != 0 {
		return nil
	}
	switch o {
	case rootSvc:
		return in.o.Sys.Chown(p, 0, in.gid)
	case svcSvc:
		return in.o.Sys.Chown(p, in.uid, in.gid)
	}
	return in.o.Sys.Chown(p, 0, 0)
}

func (in *installer) dirs(context.Context) error {
	for _, d := range []struct {
		path string
		mode fs.FileMode
		own  owner
	}{
		{"/etc/xcp", 0o755, rootRoot},
		{SecretsDir, 0o750, rootSvc},
		{SSLDir, 0o750, rootSvc},
		{"/etc/xcp/generated", 0o755, rootRoot},
		{StateDir, 0o750, svcSvc},
		{UnitDir, 0o755, rootRoot},
		{"/usr/sbin", 0o755, rootRoot},
		{"/usr/bin", 0o755, rootRoot},
	} {
		p := in.path(d.path)
		fi, err := os.Stat(p)
		if err == nil && fi.IsDir() && (fi.Mode().Perm() == d.mode || os.PathSeparator != '/') {
			if err := in.chown(p, d.own); err != nil {
				return err
			}
			continue
		}
		in.changed("directory " + d.path)
		if in.o.DryRun {
			continue
		}
		if err := os.MkdirAll(p, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(p, d.mode); err != nil {
			return err
		}
		if err := in.chown(p, d.own); err != nil {
			return err
		}
	}
	return nil
}

// writeFile writes data if the file is missing or different (or only if
// missing when keep is set). It reports whether it wrote.
func (in *installer) writeFile(p string, data []byte, mode fs.FileMode, own owner, keep bool) (bool, error) {
	full := in.path(p)
	old, err := os.ReadFile(full) //nolint:gosec // installer-controlled paths
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if exists && (keep || bytes.Equal(old, data)) {
		if !in.o.DryRun {
			if err := os.Chmod(full, mode); err != nil {
				return false, err
			}
			return false, in.chown(full, own)
		}
		return false, nil
	}
	in.changed("file " + p)
	if in.o.DryRun {
		return true, nil
	}
	// full is Options.Root joined with one of this package's constant paths.
	tmp := full + ".xcp-install.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil { //nolint:forbidigo,gosec // installer writes system files as root; G703 see above
		return false, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return false, err
	}
	if err := in.chown(tmp, own); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, full)
}

func (in *installer) binaries(context.Context) error {
	for name, dst := range Binaries {
		data, err := os.ReadFile(filepath.Join(in.o.BinDir, name)) //nolint:gosec // operator-chosen --from dir
		if err != nil {
			return fmt.Errorf("read %s from %s: %w", name, in.o.BinDir, err)
		}
		wrote, err := in.writeFile(dst, data, 0o755, rootRoot, false)
		if err != nil {
			return err
		}
		in.restart = in.restart || wrote
	}
	return nil
}

const configTemplate = `# XCP configuration (written by xcp-install; your edits are kept on re-install).
# Reference: docs/plan/01-architecture.md

[api]
listen = ":%d"
tls_cert = %q
tls_key = %q

[agent]
socket = "/run/xcp/agent.sock"
api_user = %q

[db]
path = %q

[log]
level = "info"
format = "json"
`

func (in *installer) config(context.Context) error {
	cfg := fmt.Sprintf(configTemplate, PanelPort, CertFile, KeyFile, ServiceUser, StateDir+"/xcp.db")
	_, err := in.writeFile(ConfigFile, []byte(cfg), 0o644, rootRoot, true)
	return err
}

func (in *installer) masterKey(context.Context) error {
	p := SecretsDir + "/master.key"
	if _, err := os.Stat(in.path(p)); err == nil {
		_, err := in.writeFile(p, nil, 0o640, rootSvc, true) // fix mode/owner only
		return err
	}
	key := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	_, err := in.writeFile(p, key, 0o640, rootSvc, true)
	return err
}

func (in *installer) certificate(context.Context) error {
	_, certErr := os.Stat(in.path(CertFile))
	_, keyErr := os.Stat(in.path(KeyFile))
	if certErr == nil && keyErr == nil {
		// Keep the existing pair (it may be a real certificate); fix modes only.
		if _, err := in.writeFile(KeyFile, nil, 0o640, rootSvc, true); err != nil {
			return err
		}
		_, err := in.writeFile(CertFile, nil, 0o644, rootRoot, true)
		return err
	}
	// One of the two is missing: a lone cert or key is useless, so make a new pair.
	certPEM, keyPEM, err := selfSigned(in.o.Hostname, in.o.IPs)
	if err != nil {
		return err
	}
	if _, err := in.writeFile(KeyFile, keyPEM, 0o640, rootSvc, false); err != nil {
		return err
	}
	if _, err = in.writeFile(CertFile, certPEM, 0o644, rootRoot, false); err != nil {
		return err
	}
	in.restart = true // xcp-api must load the new certificate
	return nil
}

func (in *installer) units(context.Context) error {
	ents, err := units.ReadDir("units")
	if err != nil {
		return err
	}
	for _, e := range ents {
		data, err := units.ReadFile("units/" + e.Name())
		if err != nil {
			return err
		}
		wrote, err := in.writeFile(UnitDir+"/"+e.Name(), data, 0o644, rootRoot, false)
		if err != nil {
			return err
		}
		in.reload = in.reload || wrote
		in.restart = in.restart || wrote
	}
	return nil
}

// ApacheConf includes the per-account virtual hosts the agent writes.
const ApacheConf = "/etc/apache2/conf-available/xcp.conf"

const apacheConfBody = "# Managed by XCP: per-account virtual hosts written by xcp-agent.\n" +
	"IncludeOptional /etc/apache2/xcp/vhosts/*.conf\n"

func (in *installer) web(ctx context.Context) error {
	if in.o.NoWeb {
		in.logf("    skipped (--no-web)")
		return nil
	}
	if in.o.DryRun {
		in.logf("    would install apache2 and php-fpm if missing, enable proxy_fcgi, setenvif, rewrite, headers")
		_, err := in.writeFile(ApacheConf, []byte(apacheConfBody), 0o644, rootRoot, false)
		return err
	}
	installed, err := in.o.Sys.InstallWebStack(ctx)
	if err != nil {
		return err
	}
	if installed {
		in.changed("installed apache2 and php-fpm")
	}
	if err := os.MkdirAll(in.path("/etc/apache2/conf-available"), 0o755); err != nil {
		return err
	}
	wrote, err := in.writeFile(ApacheConf, []byte(apacheConfBody), 0o644, rootRoot, false)
	if err != nil {
		return err
	}
	if wrote || installed {
		return in.o.Sys.EnableApacheConf(ctx)
	}
	return nil
}

func (in *installer) services(ctx context.Context) error {
	sys := in.o.Sys
	if in.o.DryRun {
		in.logf("    would run: systemctl daemon-reload; systemctl enable --now xcp-agent xcp-api")
		return nil
	}
	if in.reload {
		if err := sys.Systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	if err := sys.Systemctl(ctx, "enable", "--now", "xcp-agent.service", "xcp-api.service"); err != nil {
		return err
	}
	if in.restart {
		in.logf("    restarting services (binaries or units changed)")
		if err := sys.Systemctl(ctx, "restart", "xcp-agent.service", "xcp-api.service"); err != nil {
			return err
		}
	}
	ca, err := os.ReadFile(in.path(CertFile))
	if err != nil {
		return err
	}
	return sys.WaitHealthy(ctx, fmt.Sprintf("https://127.0.0.1:%d/api/v1/health", PanelPort), ca)
}

func (in *installer) admin(ctx context.Context) error {
	if in.o.DryRun {
		in.logf("    would create admin %q if no login exists", in.o.AdminUser)
		return nil
	}
	pw := in.o.AdminPassword
	generated := pw == ""
	if generated {
		pw = GeneratePassword()
	}
	created, err := in.o.Sys.CreateFirstAdmin(ctx, in.o.AdminUser, pw, generated)
	if err != nil {
		return err
	}
	in.res.AdminCreated = created
	if created && generated {
		in.res.GeneratedPassword = pw
	}
	if created {
		in.changed("admin login " + in.o.AdminUser)
	} else {
		in.logf("    logins already exist; no admin created")
	}
	return nil
}

// GeneratePassword returns a random 20-character password without
// look-alike characters (no 0/O, 1/l/I).
func GeneratePassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// Rejection sampling: only bytes below a multiple of len(alphabet) are
	// used, so every character is equally likely.
	limit := byte(256 - 256%len(alphabet))
	var sb strings.Builder
	buf := make([]byte, 64)
	for sb.Len() < 20 {
		if _, err := rand.Read(buf); err != nil {
			panic("install: crypto/rand failed: " + err.Error())
		}
		for _, c := range buf {
			if c < limit && sb.Len() < 20 {
				sb.WriteByte(alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return sb.String()
}
