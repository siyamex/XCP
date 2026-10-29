package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/tlsx"
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

// Site describes one account's websites. The agent renders all config
// itself from these fields (ADR-0004); callers never send config text.
type Site struct {
	Username    string
	UID         uint32
	Vhosts      []Vhost // the primary domain first
	PHPVersion  string  // "" = newest installed
	Suspended   bool
	MaxChildren uint32 // PHP worker processes; 0 = default
}

// Vhost is the website of one domain.
type Vhost struct {
	Name       string // "*.example.com" for a wildcard subdomain
	DocRoot    string // relative to the home folder
	Canonical  string // "", CanonicalWWW or CanonicalBare
	Redirects  []Redirect
	TLS        *TLS // served over HTTPS too; nil = HTTP only
	ForceHTTPS bool // HTTP redirects to HTTPS; needs TLS
}

// TLS is a certificate (followed by its chain) and its private key, PEM.
type TLS struct {
	CertPEM string
	KeyPEM  string
}

// Canonical host choices of a Vhost.
const (
	CanonicalWWW  = "www"  // redirect name to www.name
	CanonicalBare = "bare" // redirect www.name to name
)

// Redirect sends requests for Path and everything below it to Target.
type Redirect struct {
	Path     string // "/" = the whole site
	Target   string
	Code     int
	KeepPath bool // append the rest of the requested path to Target
}

// Bounds of one site.
const (
	MaxSiteDomains    = 200
	MaxVhostRedirects = 100
)

// CheckSite validates a site request. The fake agent uses it too.
func CheckSite(s Site) error {
	if err := CheckAccount(s.Username, s.UID, ""); err != nil {
		return err
	}
	if len(s.Vhosts) == 0 || len(s.Vhosts) > MaxSiteDomains {
		return invalid("a site needs 1 to %d domains", MaxSiteDomains)
	}
	names := map[string]bool{}
	for _, v := range s.Vhosts {
		if err := checkVhost(v); err != nil {
			return err
		}
		for _, n := range hostNames(v.Name) {
			if names[n] {
				return invalid("domain %q is served twice", n)
			}
			names[n] = true
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

// hostNames are the host names a vhost answers to.
func hostNames(name string) []string {
	if strings.HasPrefix(name, "*.") {
		return []string{name}
	}
	return []string{name, "www." + name}
}

func checkVhost(v Vhost) error {
	if n, err := validate.WildcardDomain(v.Name); err != nil || n != v.Name {
		return invalid("domain %q is not a normalised domain name", v.Name)
	}
	if d, err := validate.DocRoot(v.DocRoot); err != nil || d != v.DocRoot {
		return invalid("document root %q of %s is not a clean folder below the home folder", v.DocRoot, v.Name)
	}
	switch v.Canonical {
	case "":
	case CanonicalWWW, CanonicalBare:
		if strings.HasPrefix(v.Name, "*.") {
			return invalid("wildcard domain %s has no www form", v.Name)
		}
	default:
		return invalid("canonical %q of %s is not www or bare", v.Canonical, v.Name)
	}
	if v.TLS != nil {
		p, err := tlsx.Parse(v.TLS.CertPEM, "", v.TLS.KeyPEM)
		if err != nil {
			return invalid("certificate of %s: %v", v.Name, err)
		}
		if !tlsx.Covers(p.Leaf, v.Name) {
			return invalid("the certificate of %s does not cover that name", v.Name)
		}
	} else if v.ForceHTTPS {
		return invalid("%s cannot force HTTPS without a certificate", v.Name)
	}
	if len(v.Redirects) > MaxVhostRedirects {
		return invalid("%s has more than %d redirects", v.Name, MaxVhostRedirects)
	}
	paths := map[string]bool{}
	for _, r := range v.Redirects {
		if p, err := validate.RedirectPath(r.Path); err != nil || p != r.Path {
			return invalid("redirect path %q of %s is not a clean URL path", r.Path, v.Name)
		}
		if t, err := validate.RedirectTarget(r.Target); err != nil || t != r.Target {
			return invalid("redirect target %q of %s is not a valid URL", r.Target, v.Name)
		}
		if err := validate.RedirectCode(r.Code); err != nil {
			return invalid("redirect %s of %s: %v", r.Path, v.Name, err)
		}
		if r.KeepPath && strings.ContainsAny(r.Target, "?#") {
			return invalid("redirect %s of %s keeps the path, so its target cannot have ? or #", r.Path, v.Name)
		}
		if paths[r.Path] {
			return invalid("%s has two redirects for %s", v.Name, r.Path)
		}
		paths[r.Path] = true
	}
	return nil
}

// Web applies Apache virtual hosts and PHP-FPM pools.
type Web struct {
	Run          *execx.Runner
	Services     ServiceManager
	HomesRoot    string // /home
	VhostDir     string // /etc/apache2/xcp/vhosts
	WildcardDir  string // /etc/apache2/xcp/wildcards, included after VhostDir
	CertDir      string // /etc/xcp/ssl/sites: <user>/<domain>.crt and .key, root only
	PHPDir       string // /etc/php
	SuspendedDir string // /var/www/xcp-suspended
	LogDir       string // /var/log/apache2/xcp
	WebUser      string // www-data
	// Check validates the written configuration; nil runs "apachectl -t"
	// and "php-fpmX.Y -t" for every installed version.
	Check func(ctx context.Context, phpVersions []string) error
	mu    sync.Mutex
}

func (w *Web) poolDir(version string) string {
	return filepath.Join(w.PHPDir, version, "fpm", "pool.d")
}

// PHPVersions returns the installed PHP-FPM versions, oldest first.
func (w *Web) PHPVersions() []string {
	var out []string
	for _, v := range knownPHPVersions() {
		if _, err := os.Stat(w.poolDir(v)); err == nil {
			if _, err := os.Stat("/usr/sbin/php-fpm" + v); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

var (
	vhostTmpl = template.Must(template.New("vhost").Parse(`
{{- define "site"}}
{{- if .S.Suspended}}
    # Account suspended: every request gets the notice page.
    DocumentRoot {{.S.SuspendedDir}}
    <Directory {{.S.SuspendedDir}}>
        Require all granted
    </Directory>
    AliasMatch "^/.*$" "{{.S.SuspendedDir}}/index.html"
{{- else}}
    DocumentRoot {{.DocRoot}}
    # Symlinks in the home folder, the document root itself included, are
    # followed only when the link and its target have the same owner.
    <Directory {{.S.Home}}>
        Options SymLinksIfOwnerMatch
        AllowOverride None
        Require all denied
    </Directory>
    <Directory {{.DocRoot}}>
        Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch
        AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews,SymLinksIfOwnerMatch
        Require all granted
    </Directory>
    <FilesMatch "\.(php|phtml)$">
        SetHandler "proxy:unix:{{.S.Socket}}|fcgi://localhost"
    </FilesMatch>
{{- with .Canonical}}
    RewriteEngine On
    RewriteRule "^/\.well-known/acme-challenge/" - [L]
    RewriteCond %{HTTP_HOST} ^{{.From}}(:[0-9]+)?$ [NC]
    RewriteRule ^ %{REQUEST_SCHEME}://{{.To}}%{REQUEST_URI} [R=301,L]
{{- end}}
{{- range .Redirects}}
    {{.}}
{{- end}}
{{- end}}
    ErrorLog {{.S.LogDir}}/{{.S.Username}}.error.log
    CustomLog {{.S.LogDir}}/{{.S.Username}}.access.log combined
{{- end -}}
# Managed by XCP. Do not edit: changes are overwritten.
{{- range .Vhosts}}
<VirtualHost *:80>
    ServerName {{.ServerName}}
    ServerAlias {{.Alias}}
{{- if .HTTPSOnly}}
    # HTTPS only; certificates are still validated over HTTP.
    RewriteEngine On
    RewriteRule "^/\.well-known/acme-challenge/" - [L]
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [R=301,L]
    ErrorLog {{.S.LogDir}}/{{.S.Username}}.error.log
    CustomLog {{.S.LogDir}}/{{.S.Username}}.access.log combined
{{- else}}
{{- template "site" .}}
{{- end}}
</VirtualHost>
{{- if .CertFile}}
<VirtualHost *:443>
    ServerName {{.ServerName}}
    ServerAlias {{.Alias}}
    SSLEngine on
    SSLCertificateFile {{.CertFile}}
    SSLCertificateKeyFile {{.KeyFile}}
{{- template "site" .}}
</VirtualHost>
{{- end}}
{{- end}}
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
	Home, Socket, SuspendedDir, LogDir, WebUser string
	Vhosts                                      []vhostData
}

type vhostData struct {
	S                          *siteData
	ServerName, Alias, DocRoot string
	Canonical                  *canonicalRule
	Redirects                  []string // rendered directives
	CertFile, KeyFile          string   // set when also served over HTTPS
	HTTPSOnly                  bool     // HTTP only redirects to HTTPS
}

// canonicalRule redirects hosts matching the regex From to the host To.
type canonicalRule struct{ From, To string }

// data prepares the template fields for the wildcard or the other vhosts.
// The socket name includes the PHP version: when a site switches version,
// the old FPM unlinks its socket on reload, which must not be the new FPM's.
func (w *Web) data(s Site, wildcards bool) siteData {
	d := &siteData{
		Site: s, Home: path.Join(w.HomesRoot, s.Username),
		Socket:       "/run/php/xcp-" + s.Username + "-" + s.PHPVersion + ".sock",
		SuspendedDir: w.SuspendedDir, LogDir: w.LogDir, WebUser: w.WebUser,
	}
	if d.MaxChildren == 0 {
		d.MaxChildren = 10
	}
	for _, v := range s.Vhosts {
		if strings.HasPrefix(v.Name, "*.") == wildcards {
			d.Vhosts = append(d.Vhosts, w.vhostOf(d, v))
		}
	}
	return *d
}

// certBase names the certificate files of a vhost.
func certBase(name string) string {
	if base, ok := strings.CutPrefix(name, "*."); ok {
		return "_wildcard." + base
	}
	return name
}

func (w *Web) vhostOf(s *siteData, v Vhost) vhostData {
	d := vhostData{S: s, ServerName: v.Name, Alias: "www." + v.Name, DocRoot: s.Home + "/" + v.DocRoot}
	if v.TLS != nil {
		dir := path.Join(w.CertDir, s.Username)
		d.CertFile, d.KeyFile = path.Join(dir, certBase(v.Name)+".crt"), path.Join(dir, certBase(v.Name)+".key")
		d.HTTPSOnly = v.ForceHTTPS && !s.Suspended
	}
	if base, ok := strings.CutPrefix(v.Name, "*."); ok {
		d.ServerName, d.Alias = "wildcard."+base, v.Name
	}
	switch v.Canonical {
	case CanonicalWWW:
		d.Canonical = &canonicalRule{From: regexp.QuoteMeta(v.Name), To: "www." + v.Name}
	case CanonicalBare:
		d.Canonical = &canonicalRule{From: regexp.QuoteMeta("www." + v.Name), To: v.Name}
	}
	rs := slices.Clone(v.Redirects)
	// Longest path first: Apache uses the first redirect that matches.
	slices.SortStableFunc(rs, func(a, b Redirect) int { return len(b.Path) - len(a.Path) })
	for _, r := range rs {
		d.Redirects = append(d.Redirects, redirectLine(r))
	}
	return d
}

// redirectLine renders a redirect for mod_alias. CheckSite has made sure
// paths and targets hold no quotes, backslashes, spaces or '$'. A redirect
// of the whole site leaves out the path certificates are validated under.
func redirectLine(r Redirect) string {
	const notACME = `(?!\.well-known/acme-challenge/)`
	switch {
	case r.KeepPath && r.Path == "/":
		t := r.Target
		if !strings.HasSuffix(t, "/") {
			t += "/"
		}
		return fmt.Sprintf(`RedirectMatch %d "^/%s(.*)$" "%s$1"`, r.Code, notACME, t)
	case r.KeepPath:
		// Redirect appends what follows the path, starting with "/".
		return fmt.Sprintf(`Redirect %d "%s" "%s"`, r.Code, r.Path, strings.TrimSuffix(r.Target, "/"))
	case r.Path == "/":
		return fmt.Sprintf(`RedirectMatch %d "^/%s" "%s"`, r.Code, notACME, r.Target)
	default:
		return fmt.Sprintf(`RedirectMatch %d "^%s(/.*)?$" "%s"`, r.Code, regexp.QuoteMeta(r.Path), r.Target)
	}
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
	unit      string // the service that reads it
	private   bool   // root only (0600): private keys
}

func (f managedFile) mode() fs.FileMode {
	if f.private {
		return 0o600
	}
	return 0o644
}

const apacheUnit = "apache2.service"

func fpmUnit(version string) string { return "php" + version + "-fpm.service" }

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
	s.PHPVersion = version
	d, wild := w.data(s, false), w.data(s, true)
	files := []managedFile{
		{dir: w.VhostDir, name: s.Username + ".conf", content: render(vhostTmpl, d), unit: apacheUnit},
		// Wildcards load after every other vhost, so "*.example.com" never
		// catches a name that another vhost (of any account) serves.
		{dir: w.WildcardDir, name: s.Username + ".conf", unit: apacheUnit},
	}
	if len(wild.Vhosts) > 0 {
		files[1].content = render(vhostTmpl, wild)
	}
	for _, v := range installed {
		f := managedFile{dir: w.poolDir(v), name: "xcp-" + s.Username + ".conf", unit: fpmUnit(v)}
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
	if err := w.ensureDocRoots(s); err != nil {
		return SiteResult{}, err
	}
	certs, err := w.certFiles(s)
	if err != nil {
		return SiteResult{}, err
	}
	changed, err := w.write(ctx, append(files, certs...), installed)
	return SiteResult{Changed: changed, PHPVersion: version}, err
}

// certFiles are the certificate and key files of the account's HTTPS
// vhosts (re-encoded by tlsx, so nothing else reaches them), and removals
// for the files that no vhost uses any more.
func (w *Web) certFiles(s Site) ([]managedFile, error) {
	dir := filepath.Join(w.CertDir, s.Username)
	want := map[string]bool{}
	var out []managedFile
	for _, v := range s.Vhosts {
		if v.TLS == nil {
			continue
		}
		p, err := tlsx.Parse(v.TLS.CertPEM, "", v.TLS.KeyPEM)
		if err != nil {
			return nil, invalid("certificate of %s: %v", v.Name, err)
		}
		b := certBase(v.Name)
		out = append(out,
			managedFile{dir: dir, name: b + ".crt", content: []byte(p.CertPEM), unit: apacheUnit},
			managedFile{dir: dir, name: b + ".key", content: []byte(p.KeyPEM), unit: apacheUnit, private: true})
		want[b+".crt"], want[b+".key"] = true, true
	}
	if len(out) > 0 {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return append(out, w.staleCerts(dir, want)...), nil
}

// staleCerts are removals for the files in dir that are not in keep.
func (w *Web) staleCerts(dir string, keep map[string]bool) []managedFile {
	ents, _ := os.ReadDir(dir) // a missing folder has nothing to remove
	var out []managedFile
	for _, e := range ents {
		if e.Type().IsRegular() && !keep[e.Name()] {
			out = append(out, managedFile{dir: dir, name: e.Name(), unit: apacheUnit})
		}
	}
	return out
}

// ensureDocRoots creates missing document roots below the account's home,
// through fsx (no symlinks followed): folders on the way get 0711 so the web
// server can pass, the document root 0750 with the web server's group and a
// placeholder page. Whatever exists already is left as it is.
func (w *Web) ensureDocRoots(s Site) error {
	uid := int(s.UID)
	gid, webGID := uid, uid
	if g, err := user.LookupGroup(s.Username); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if g, err := user.LookupGroup(w.WebUser); err == nil {
		webGID, _ = strconv.Atoi(g.Gid)
	}
	root, err := fsx.OpenRoot(filepath.Join(w.HomesRoot, s.Username))
	if err != nil {
		return err
	}
	defer root.Close()
	for _, v := range s.Vhosts {
		if err := makeDocRoot(root, v, uid, gid, webGID); err != nil {
			return fmt.Errorf("document root %s of %s: %w", v.DocRoot, v.Name, err)
		}
	}
	return nil
}

func makeDocRoot(root *fsx.Root, v Vhost, uid, gid, webGID int) error {
	elems := strings.Split(v.DocRoot, "/")
	for i := range elems {
		rel := strings.Join(elems[:i+1], "/")
		if _, err := root.Lstat(rel); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		last := i == len(elems)-1
		mode, group := fs.FileMode(0o711), gid
		if last {
			mode, group = 0o750, webGID
		}
		if err := root.Mkdir(rel, mode); err != nil {
			return err
		}
		if err := root.Chmod(rel, mode); err != nil { // the umask must not reduce it
			return err
		}
		if last {
			page := rel + "/index.html"
			if err := root.WriteFileAtomic(page, []byte(indexPage(strings.TrimPrefix(v.Name, "*."), v.DocRoot)), 0o644); err != nil {
				return err
			}
			if err := root.Chown(page, uid, gid); err != nil {
				return err
			}
		}
		// Owned by root until here, so the user cannot interfere with the setup.
		if err := root.Chown(rel, uid, group); err != nil {
			return err
		}
	}
	return nil
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
	files := []managedFile{
		{dir: w.VhostDir, name: username + ".conf", unit: apacheUnit},
		{dir: w.WildcardDir, name: username + ".conf", unit: apacheUnit},
	}
	for _, v := range installed {
		files = append(files, managedFile{dir: w.poolDir(v), name: "xcp-" + username + ".conf", unit: fpmUnit(v)})
	}
	certDir := filepath.Join(w.CertDir, username)
	w.mu.Lock()
	defer w.mu.Unlock()
	changed, err := w.write(ctx, append(files, w.staleCerts(certDir, nil)...), installed)
	if err == nil {
		_ = os.Remove(certDir) // empty now
	}
	return changed, err
}

// ensureSupport creates the vhost and log folders and the suspended page.
func (w *Web) ensureSupport() error {
	for _, dir := range []string{w.VhostDir, w.WildcardDir, w.LogDir, w.SuspendedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: read by Apache
			return err
		}
	}
	if err := os.MkdirAll(w.CertDir, 0o700); err != nil { // private keys: root only
		return err
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

// write applies files, validates, reloads, and rolls back on failure.
func (w *Web) write(ctx context.Context, files []managedFile, installed []string) (bool, error) {
	type prev struct {
		f       managedFile
		old     []byte
		existed bool
	}
	var done []prev
	var changed []managedFile
	restore := func() {
		for _, p := range done {
			root, err := fsx.OpenRoot(p.f.dir)
			if err != nil {
				continue
			}
			if p.existed {
				_ = root.WriteFileAtomic(p.f.name, p.old, p.f.mode())
			} else {
				_ = root.Remove(p.f.name)
			}
			root.Close()
		}
	}
	for _, f := range files {
		root, err := fsx.OpenRoot(f.dir)
		if errors.Is(err, fs.ErrNotExist) && f.content == nil {
			continue // nothing to remove
		}
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
			err = root.WriteFileAtomic(f.name, f.content, f.mode())
		}
		root.Close()
		if err != nil {
			restore()
			return false, err
		}
		done = append(done, prev{f, old, existed})
		changed = append(changed, f)
	}
	if len(changed) == 0 {
		return false, nil
	}
	check := w.Check
	if check == nil {
		check = w.check
	}
	if err := check(ctx, installed); err != nil {
		restore()
		return false, err
	}
	// reload-or-restart also starts a service that is not running.
	var reloaded []string
	for _, unit := range reloadOrder(changed) {
		if err := w.Services.Do(ctx, unit, ActionReloadOrRestart); err != nil {
			// Put the old files back so that a retry writes and reloads
			// again, and let what was already reloaded read them again.
			restore()
			for _, u := range reloaded {
				_ = w.Services.Do(ctx, u, ActionReloadOrRestart)
			}
			return false, fmt.Errorf("reload %s: %w", unit, err)
		}
		reloaded = append(reloaded, unit)
	}
	return true, nil
}

// reloadOrder lists the services to reload for the changed files: PHP-FPM
// versions with a new or changed pool first, so their sockets exist before
// Apache uses them, then Apache, then the versions that only lost a pool.
func reloadOrder(changed []managedFile) []string {
	var gained, apache, lost []string
	for _, f := range changed {
		switch {
		case f.unit == apacheUnit:
			apache = []string{apacheUnit}
		case f.content != nil:
			gained = append(gained, f.unit)
		default:
			lost = append(lost, f.unit)
		}
	}
	return slices.Concat(gained, apache, lost)
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
