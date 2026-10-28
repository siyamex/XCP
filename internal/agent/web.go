package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// ApachectlPath is Apache's control program, used for "apachectl -t".
const ApachectlPath = "/usr/sbin/apachectl"

// PHPFPMPaths lists every php-fpm binary the agent may run (for "-t"); a
// fixed set so the execx allow-list stays static.
func PHPFPMPaths() []string {
	var out []string
	for _, v := range knownPHPVersions() {
		out = append(out, "/usr/sbin/php-fpm"+v)
	}
	return out
}

func knownPHPVersions() []string {
	vs := []string{"5.6"}
	for minor := 0; minor <= 4; minor++ {
		vs = append(vs, fmt.Sprintf("7.%d", minor))
	}
	for minor := 0; minor <= 9; minor++ {
		vs = append(vs, fmt.Sprintf("8.%d", minor))
	}
	return vs
}

var phpVersionRe = regexp.MustCompile(`^[5-9]\.[0-9]$`)

// Site describes one account's website. The agent renders all config
// itself from these fields (ADR-0004); callers never send config text.
type Site struct {
	Username    string
	UID         uint32
	Domains     []string // first one is the primary domain
	PHPVersion  string   // "" = newest installed
	Suspended   bool
	MaxChildren uint32 // PHP worker processes; 0 = default
}

// MaxSiteDomains bounds the domains of one site.
const MaxSiteDomains = 200

// CheckSite validates a site request. The fake agent uses it too.
func CheckSite(s Site) error {
	if err := CheckAccount(s.Username, s.UID, ""); err != nil {
		return err
	}
	if len(s.Domains) == 0 || len(s.Domains) > MaxSiteDomains {
		return invalid("a site needs 1 to %d domains", MaxSiteDomains)
	}
	for _, d := range s.Domains {
		if n, err := validate.Domain(d); err != nil || n != d {
			return invalid("domain %q is not a normalised domain name", d)
		}
	}
	if s.PHPVersion != "" && !phpVersionRe.MatchString(s.PHPVersion) {
		return invalid("PHP version %q is not like 8.3", s.PHPVersion)
	}
	if s.MaxChildren > 200 {
		return invalid("max_children above 200")
	}
	return nil
}

// Web applies Apache virtual hosts and PHP-FPM pools.
type Web struct {
	Run          *execx.Runner
	Services     ServiceManager
	HomesRoot    string // /home
	VhostDir     string // /etc/apache2/xcp/vhosts
	PHPDir       string // /etc/php
	SuspendedDir string // /var/www/xcp-suspended
	LogDir       string // /var/log/apache2/xcp
	WebUser      string // www-data
	mu           sync.Mutex
}

// PHPVersions returns the installed PHP-FPM versions, oldest first.
func (w *Web) PHPVersions() []string {
	var out []string
	for _, v := range knownPHPVersions() {
		if _, err := os.Stat(filepath.Join(w.PHPDir, v, "fpm", "pool.d")); err == nil {
			if _, err := os.Stat("/usr/sbin/php-fpm" + v); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

var (
	vhostTmpl = template.Must(template.New("vhost").Parse(`# Managed by XCP. Do not edit: changes are overwritten.
<VirtualHost *:80>
    ServerName {{.Primary}}
    ServerAlias {{range $i, $a := .Aliases}}{{if $i}} {{end}}{{$a}}{{end}}
{{- if .Suspended}}
    # Account suspended: every request gets the notice page.
    DocumentRoot {{.SuspendedDir}}
    <Directory {{.SuspendedDir}}>
        Require all granted
    </Directory>
    AliasMatch "^/.*$" "{{.SuspendedDir}}/index.html"
{{- else}}
    DocumentRoot {{.DocRoot}}
    <Directory {{.DocRoot}}>
        Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch
        AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews,SymLinksIfOwnerMatch
        Require all granted
    </Directory>
    <FilesMatch "\.(php|phtml)$">
        SetHandler "proxy:unix:{{.Socket}}|fcgi://localhost"
    </FilesMatch>
{{- end}}
    ErrorLog {{.LogDir}}/{{.Username}}.error.log
    CustomLog {{.LogDir}}/{{.Username}}.access.log combined
</VirtualHost>
`))
	poolTmpl = template.Must(template.New("pool").Parse(`; Managed by XCP. Do not edit: changes are overwritten.
[xcp-{{.Username}}]
user = {{.Username}}
group = {{.Username}}
listen = {{.Socket}}
listen.owner = {{.WebUser}}
listen.group = {{.WebUser}}
listen.mode = 0660
pm = ondemand
pm.max_children = {{.MaxChildren}}
pm.process_idle_timeout = 30s
pm.max_requests = 500
chdir = /
security.limit_extensions = .php .phtml
php_admin_value[open_basedir] = {{.Home}}/:/usr/share/php/
php_admin_value[upload_tmp_dir] = {{.Home}}/tmp
php_admin_value[session.save_path] = {{.Home}}/tmp
php_admin_value[sys_temp_dir] = {{.Home}}/tmp
php_admin_flag[allow_url_include] = off
`))
)

type siteData struct {
	Site
	Primary, DocRoot, Home, Socket, SuspendedDir, LogDir, WebUser string
	Aliases                                                       []string
}

func (w *Web) data(s Site) siteData {
	d := siteData{
		Site: s, Primary: s.Domains[0], Home: path.Join(w.HomesRoot, s.Username),
		Socket: "/run/php/xcp-" + s.Username + ".sock", SuspendedDir: w.SuspendedDir, LogDir: w.LogDir, WebUser: w.WebUser,
	}
	d.DocRoot = d.Home + "/public_html"
	d.Aliases = []string{"www." + s.Domains[0]}
	for _, dom := range s.Domains[1:] {
		d.Aliases = append(d.Aliases, dom, "www."+dom)
	}
	if d.MaxChildren == 0 {
		d.MaxChildren = 10
	}
	return d
}

func render(t *template.Template, d siteData) []byte {
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		panic("agent: template: " + err.Error()) // templates are static and fields validated
	}
	return b.Bytes()
}

// managedFile is one config file the agent writes for a site.
type managedFile struct {
	dir, name string
	content   []byte // nil = must not exist
}

// SiteResult reports what Apply did.
type SiteResult struct {
	Changed    bool
	PHPVersion string
}

// Apply writes the site's vhost and pool, validates the whole configuration,
// rolls back on failure, and reloads Apache and PHP-FPM gracefully.
func (w *Web) Apply(ctx context.Context, s Site) (SiteResult, error) {
	if err := CheckSite(s); err != nil {
		return SiteResult{}, err
	}
	if _, err := os.Stat(ApachectlPath); err != nil {
		return SiteResult{}, fmt.Errorf("%w: Apache (%s)", ErrNotInstalled, ApachectlPath)
	}
	installed := w.PHPVersions()
	if len(installed) == 0 {
		return SiteResult{}, fmt.Errorf("%w: no PHP-FPM version", ErrNotInstalled)
	}
	version := s.PHPVersion
	if version == "" {
		version = installed[len(installed)-1]
	}
	if !slices.Contains(installed, version) {
		return SiteResult{}, invalid("PHP %s is not installed (installed: %s)", version, strings.Join(installed, ", "))
	}
	d := w.data(s)
	files := []managedFile{{dir: w.VhostDir, name: s.Username + ".conf", content: render(vhostTmpl, d)}}
	for _, v := range installed {
		f := managedFile{dir: filepath.Join(w.PHPDir, v, "fpm", "pool.d"), name: "xcp-" + s.Username + ".conf"}
		if v == version && !s.Suspended { // a suspended account runs no PHP at all
			f.content = render(poolTmpl, d)
		}
		files = append(files, f)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.ensureSupport(); err != nil {
		return SiteResult{}, err
	}
	changed, err := w.write(ctx, files, installed)
	return SiteResult{Changed: changed, PHPVersion: version}, err
}

// Remove deletes the site's vhost and pools.
func (w *Web) Remove(ctx context.Context, username string) (bool, error) {
	if err := validate.Username(username); err != nil {
		return false, invalid("username: %v", err)
	}
	if _, err := os.Stat(ApachectlPath); err != nil {
		return false, nil // nothing can have been written without Apache
	}
	installed := w.PHPVersions()
	files := []managedFile{{dir: w.VhostDir, name: username + ".conf"}}
	for _, v := range installed {
		files = append(files, managedFile{dir: filepath.Join(w.PHPDir, v, "fpm", "pool.d"), name: "xcp-" + username + ".conf"})
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.write(ctx, files, installed)
}

// ensureSupport creates the vhost and log folders and the suspended page.
func (w *Web) ensureSupport() error {
	for _, dir := range []string{w.VhostDir, w.LogDir, w.SuspendedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: read by Apache
			return err
		}
	}
	page := filepath.Join(w.SuspendedDir, "index.html")
	if _, err := os.Stat(page); err == nil {
		return nil
	}
	root, err := fsx.OpenRoot(w.SuspendedDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFileAtomic("index.html", []byte("<!doctype html>\n<meta charset=\"utf-8\">\n<title>Suspended</title>\n"+
		"<p style=\"font-family:sans-serif;margin:3em\">This website is currently suspended.</p>\n"), 0o644)
}

// write applies files, validates, rolls back on failure and reloads.
func (w *Web) write(ctx context.Context, files []managedFile, installed []string) (bool, error) {
	type prev struct {
		f       managedFile
		old     []byte
		existed bool
	}
	var done []prev
	changed := false
	restore := func() {
		for _, p := range done {
			root, err := fsx.OpenRoot(p.f.dir)
			if err != nil {
				continue
			}
			if p.existed {
				_ = root.WriteFileAtomic(p.f.name, p.old, 0o644)
			} else {
				_ = root.Remove(p.f.name)
			}
			root.Close()
		}
	}
	for _, f := range files {
		root, err := fsx.OpenRoot(f.dir)
		if err != nil {
			restore()
			return false, err
		}
		old, rerr := root.ReadFile(f.name, MaxManagedFileSize)
		existed := rerr == nil
		if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			root.Close()
			restore()
			return false, rerr
		}
		switch {
		case f.content == nil && !existed, f.content != nil && existed && bytes.Equal(old, f.content):
			root.Close()
			continue
		case f.content == nil:
			err = root.Remove(f.name)
		default:
			err = root.WriteFileAtomic(f.name, f.content, 0o644)
		}
		root.Close()
		if err != nil {
			restore()
			return false, err
		}
		done = append(done, prev{f, old, existed})
		changed = true
	}
	if !changed {
		return false, nil
	}
	if err := w.check(ctx, installed); err != nil {
		restore()
		return false, err
	}
	// PHP-FPM first, so the socket exists before Apache sends requests to it.
	for _, v := range installed {
		if err := w.Services.Do(ctx, "php"+v+"-fpm.service", ActionReload); err != nil {
			return true, fmt.Errorf("reload php%s-fpm: %w", v, err)
		}
	}
	return true, w.Services.Do(ctx, "apache2.service", ActionReload)
}

// check runs Apache's and PHP-FPM's own configuration tests.
func (w *Web) check(ctx context.Context, installed []string) error {
	cmds := []execx.Cmd{{Path: ApachectlPath, Args: []string{"-t"}}}
	for _, v := range installed {
		cmds = append(cmds, execx.Cmd{Path: "/usr/sbin/php-fpm" + v, Args: []string{"-t"}})
	}
	for _, c := range cmds {
		res, err := w.Run.Run(ctx, c)
		var ee *execx.ExitError
		if errors.As(err, &ee) {
			return &ValidationFailedError{Output: strings.TrimSpace(string(res.Stderr) + "\n" + string(res.Stdout))}
		}
		if err != nil {
			return err
		}
	}
	return nil
}
