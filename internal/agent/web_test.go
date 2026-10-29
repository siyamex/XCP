package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/fsx"
)

func testWeb() *Web {
	return &Web{
		HomesRoot: "/home", VhostDir: "/etc/apache2/xcp/vhosts", WildcardDir: "/etc/apache2/xcp/wildcards", CertDir: "/etc/xcp/ssl/sites", PHPDir: "/etc/php",
		SuspendedDir: "/var/www/xcp-suspended", LogDir: "/var/log/apache2/xcp", WebUser: "www-data",
	}
}

// demoSite has a primary domain with a canonical host and redirects, an
// addon domain, and a wildcard subdomain.
func demoSite() Site {
	return Site{Username: "demo1", UID: 10000, PHPVersion: "8.3", Vhosts: []Vhost{
		{Name: "demo1.example", DocRoot: "public_html", Canonical: CanonicalBare, Redirects: []Redirect{
			{Path: "/old", Target: "https://demo1.example/new", Code: 301, KeepPath: true},
			{Path: "/old/promo", Target: "https://shop.example/?ref=promo", Code: 302},
		}},
		{Name: "shop.example", DocRoot: "domains/shop.example"},
		{Name: "*.demo1.example", DocRoot: "domains/_wildcard.demo1.example"},
	}}
}

func TestVhostGolden(t *testing.T) {
	got := string(render(vhostTmpl, testWeb().data(demoSite(), false)))
	want := `# Managed by XCP. Do not edit: changes are overwritten.
<VirtualHost *:80>
    ServerName demo1.example
    ServerAlias www.demo1.example
    DocumentRoot /home/demo1/public_html
    # Symlinks in the home folder, the document root itself included, are
    # followed only when the link and its target have the same owner.
    <Directory /home/demo1>
        Options SymLinksIfOwnerMatch
        AllowOverride None
        Require all denied
    </Directory>
    <Directory /home/demo1/public_html>
        Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch
        AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews,SymLinksIfOwnerMatch
        Require all granted
    </Directory>
    <FilesMatch "\.(php|phtml)$">
        SetHandler "proxy:unix:/run/php/xcp-demo1-8.3.sock|fcgi://localhost"
    </FilesMatch>
    RewriteEngine On
    RewriteRule "^/\.well-known/acme-challenge/" - [L]
    RewriteCond %{HTTP_HOST} ^www\.demo1\.example(:[0-9]+)?$ [NC]
    RewriteRule ^ %{REQUEST_SCHEME}://demo1.example%{REQUEST_URI} [R=301,L]
    RedirectMatch 302 "^/old/promo(/.*)?$" "https://shop.example/?ref=promo"
    Redirect 301 "/old" "https://demo1.example/new"
    ErrorLog /var/log/apache2/xcp/demo1.error.log
    CustomLog /var/log/apache2/xcp/demo1.access.log combined
</VirtualHost>
<VirtualHost *:80>
    ServerName shop.example
    ServerAlias www.shop.example
    DocumentRoot /home/demo1/domains/shop.example
    # Symlinks in the home folder, the document root itself included, are
    # followed only when the link and its target have the same owner.
    <Directory /home/demo1>
        Options SymLinksIfOwnerMatch
        AllowOverride None
        Require all denied
    </Directory>
    <Directory /home/demo1/domains/shop.example>
        Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch
        AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews,SymLinksIfOwnerMatch
        Require all granted
    </Directory>
    <FilesMatch "\.(php|phtml)$">
        SetHandler "proxy:unix:/run/php/xcp-demo1-8.3.sock|fcgi://localhost"
    </FilesMatch>
    ErrorLog /var/log/apache2/xcp/demo1.error.log
    CustomLog /var/log/apache2/xcp/demo1.access.log combined
</VirtualHost>
`
	if got != want {
		t.Fatalf("vhost:\n%s\nwant:\n%s", got, want)
	}
}

func TestWildcardVhostsGoToTheirOwnFile(t *testing.T) {
	got := string(render(vhostTmpl, testWeb().data(demoSite(), true)))
	for _, must := range []string{"ServerName wildcard.demo1.example\n", "ServerAlias *.demo1.example\n", "DocumentRoot /home/demo1/domains/_wildcard.demo1.example\n"} {
		if !strings.Contains(got, must) {
			t.Errorf("wildcard vhosts lack %q:\n%s", must, got)
		}
	}
	if strings.Count(got, "<VirtualHost") != 1 {
		t.Errorf("wildcard file must hold only the wildcard vhost:\n%s", got)
	}
}

func TestRedirectLines(t *testing.T) {
	cases := map[Redirect]string{
		{Path: "/", Target: "https://new.example", Code: 301, KeepPath: true}:             `RedirectMatch 301 "^/(?!\.well-known/acme-challenge/)(.*)$" "https://new.example/$1"`,
		{Path: "/", Target: "https://new.example/x/", Code: 308, KeepPath: true}:          `RedirectMatch 308 "^/(?!\.well-known/acme-challenge/)(.*)$" "https://new.example/x/$1"`,
		{Path: "/docs", Target: "https://new.example/manual/", Code: 307, KeepPath: true}: `Redirect 307 "/docs" "https://new.example/manual"`,
		{Path: "/", Target: "https://new.example/?a=1&b=2", Code: 302}:                    `RedirectMatch 302 "^/(?!\.well-known/acme-challenge/)" "https://new.example/?a=1&b=2"`,
		{Path: "/a.b/c-d", Target: "http://x.example/", Code: 301}:                        `RedirectMatch 301 "^/a\.b/c-d(/.*)?$" "http://x.example/"`,
	}
	for r, want := range cases {
		if got := redirectLine(r); got != want {
			t.Errorf("redirectLine(%+v)\n got %s\nwant %s", r, got, want)
		}
	}
}

func TestSuspendedVhostServesNoticeOnly(t *testing.T) {
	s := demoSite()
	s.Suspended = true
	got := string(render(vhostTmpl, testWeb().data(s, false)))
	for _, must := range []string{`DocumentRoot /var/www/xcp-suspended`, `AliasMatch "^/.*$" "/var/www/xcp-suspended/index.html"`} {
		if !strings.Contains(got, must) {
			t.Errorf("suspended vhost lacks %q:\n%s", must, got)
		}
	}
	for _, mustNot := range []string{"public_html", "proxy:unix", "Redirect", "Rewrite"} {
		if strings.Contains(got, mustNot) {
			t.Errorf("suspended vhost still serves the site (%q):\n%s", mustNot, got)
		}
	}
	if strings.Count(got, "/var/www/xcp-suspended/index.html") != 2 {
		t.Errorf("every domain must show the notice:\n%s", got)
	}
}

func TestPoolGolden(t *testing.T) {
	s := demoSite()
	s.MaxChildren = 4
	got := string(render(poolTmpl, testWeb().data(s, false)))
	want := `; Managed by XCP. Do not edit: changes are overwritten.
[xcp-demo1]
user = demo1
group = demo1
listen = /run/php/xcp-demo1-8.3.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 30s
pm.max_requests = 500
chdir = /
security.limit_extensions = .php .phtml
php_admin_value[open_basedir] = /home/demo1/:/usr/share/php/
php_admin_value[upload_tmp_dir] = /home/demo1/tmp
php_admin_value[session.save_path] = /home/demo1/tmp
php_admin_value[sys_temp_dir] = /home/demo1/tmp
php_admin_flag[allow_url_include] = off
`
	if got != want {
		t.Fatalf("pool:\n%s\nwant:\n%s", got, want)
	}
	if def := string(render(poolTmpl, testWeb().data(Site{Username: "a", UID: 10000}, false))); !strings.Contains(def, "pm.max_children = 10") {
		t.Fatal("default max_children should be 10")
	}
}

func TestMakeDocRootCreatesOnlyWhatIsMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs chown (Linux)")
	}
	home := t.TempDir()
	root, err := fsx.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	uid, gid := os.Getuid(), os.Getgid()
	mode := func(rel string) fs.FileMode {
		fi, err := os.Lstat(filepath.Join(home, rel))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	if err := makeDocRoot(root, Vhost{Name: "*.shop.example", DocRoot: "domains/shop"}, uid, gid, gid); err != nil {
		t.Fatal(err)
	}
	if mode("domains") != 0o711 || mode("domains/shop") != 0o750 {
		t.Fatalf("modes: domains %v, docroot %v", mode("domains"), mode("domains/shop"))
	}
	if b, _ := os.ReadFile(filepath.Join(home, "domains/shop/index.html")); !strings.Contains(string(b), "<b>shop.example</b> is hosted") {
		t.Fatalf("placeholder page = %q", b)
	}

	// What the user changed stays as it is.
	os.Chmod(filepath.Join(home, "domains/shop"), 0o755)
	os.Remove(filepath.Join(home, "domains/shop/index.html"))
	if err := makeDocRoot(root, Vhost{Name: "shop.example", DocRoot: "domains/shop"}, uid, gid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "domains/shop/index.html")); mode("domains/shop") != 0o755 || err == nil {
		t.Fatal("an existing document root was changed")
	}

	// A symlink on the way is refused, never followed.
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	if err := makeDocRoot(root, Vhost{Name: "x.example", DocRoot: "link/www"}, uid, gid, gid); err == nil {
		t.Fatal("document root created through a symlink")
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("wrote outside the home folder: %v", ents)
	}
}

// webOnDisk returns a Web writing into temp folders, with a fake service
// manager and a config check that always passes.
func webOnDisk(t *testing.T) (*Web, *fakeManager) {
	t.Helper()
	m := &fakeManager{}
	w := testWeb()
	root := t.TempDir()
	w.VhostDir, w.PHPDir, w.Services = filepath.Join(root, "vhosts"), filepath.Join(root, "php"), m
	w.Check = func(context.Context, []string) error { return nil }
	for _, dir := range []string{w.VhostDir, w.poolDir("8.2"), w.poolDir("8.3")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return w, m
}

// siteFiles is the vhost and the 8.2 and 8.3 pools of demo1; "" = no file.
func siteFiles(w *Web, vhost, pool82, pool83 string) []managedFile {
	content := func(s string) []byte {
		if s == "" {
			return nil
		}
		return []byte(s)
	}
	return []managedFile{
		{dir: w.VhostDir, name: "demo1.conf", content: content(vhost), unit: apacheUnit},
		{dir: w.poolDir("8.2"), name: "xcp-demo1.conf", content: content(pool82), unit: fpmUnit("8.2")},
		{dir: w.poolDir("8.3"), name: "xcp-demo1.conf", content: content(pool83), unit: fpmUnit("8.3")},
	}
}

func TestSiteWriteReloadsWhatChanged(t *testing.T) {
	w, m := webOnDisk(t)
	const fpm82, fpm83, apache = "reload-or-restart php8.2-fpm.service", "reload-or-restart php8.3-fpm.service", "reload-or-restart apache2.service"
	steps := []struct {
		name                  string
		vhost, pool82, pool83 string
		want                  []string
	}{
		{"create", "v1", "", "p1", []string{fpm83, apache}},
		{"unchanged", "v1", "", "p1", nil},
		{"pool only", "v1", "", "p2", []string{fpm83}},
		// The new version's socket must exist before Apache uses it; the old
		// version drops its pool last.
		{"switch to 8.2", "v2", "p2", "", []string{fpm82, apache, fpm83}},
		{"remove", "", "", "", []string{apache, fpm82}},
	}
	for _, s := range steps {
		m.calls = nil
		changed, err := w.write(ctx, siteFiles(w, s.vhost, s.pool82, s.pool83), []string{"8.2", "8.3"})
		if err != nil || changed != (s.want != nil) || !slices.Equal(m.calls, s.want) {
			t.Fatalf("%s: changed=%v err=%v calls=%q, want %q", s.name, changed, err, m.calls, s.want)
		}
	}
}

func TestSiteReloadFailureRollsBackSoRetryReloads(t *testing.T) {
	w, m := webOnDisk(t)
	files := siteFiles(w, "v1", "", "p1")
	m.fail = apacheUnit
	if _, err := w.write(ctx, files, []string{"8.3"}); err == nil || !strings.Contains(err.Error(), "apache2.service failed") {
		t.Fatalf("err = %v", err)
	}
	// PHP-FPM, already reloaded, reads the restored (absent) pool again.
	want := []string{"reload-or-restart php8.3-fpm.service", "reload-or-restart apache2.service", "reload-or-restart php8.3-fpm.service"}
	if !slices.Equal(m.calls, want) {
		t.Fatalf("calls = %q, want %q", m.calls, want)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(f.dir, f.name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left behind after a failed reload: %v", f.name, err)
		}
	}
	// The job is retried: it must write and reload again, not find "nothing changed".
	m.fail, m.calls = "", nil
	if changed, err := w.write(ctx, files, []string{"8.3"}); err != nil || !changed || len(m.calls) != 2 {
		t.Fatalf("retry: changed=%v err=%v calls=%q", changed, err, m.calls)
	}
}

// testTLS is a self-signed certificate for names, with its key.
func testTLS(t *testing.T, names ...string) *TLS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	return &TLS{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})),
	}
}

func TestHTTPSVhosts(t *testing.T) {
	s := Site{Username: "demo1", UID: 10000, PHPVersion: "8.3", Vhosts: []Vhost{
		{Name: "secure.example", DocRoot: "public_html", TLS: testTLS(t, "secure.example"), ForceHTTPS: true},
		{Name: "both.example", DocRoot: "public_html", TLS: testTLS(t, "both.example")},
	}}
	if err := CheckSite(s); err != nil {
		t.Fatal(err)
	}
	got := string(render(vhostTmpl, testWeb().data(s, false)))
	httpOnlyRedirect := `<VirtualHost *:80>
    ServerName secure.example
    ServerAlias www.secure.example
    # HTTPS only; certificates are still validated over HTTP.
    RewriteEngine On
    RewriteRule "^/\.well-known/acme-challenge/" - [L]
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [R=301,L]
    ErrorLog /var/log/apache2/xcp/demo1.error.log
    CustomLog /var/log/apache2/xcp/demo1.access.log combined
</VirtualHost>
<VirtualHost *:443>
    ServerName secure.example
    ServerAlias www.secure.example
    SSLEngine on
    SSLCertificateFile /etc/xcp/ssl/sites/demo1/secure.example.crt
    SSLCertificateKeyFile /etc/xcp/ssl/sites/demo1/secure.example.key
    DocumentRoot /home/demo1/public_html
`
	if !strings.Contains(got, httpOnlyRedirect) {
		t.Fatalf("force-HTTPS vhosts:\n%s", got)
	}
	if strings.Count(got, "<VirtualHost *:443>") != 2 || strings.Count(got, "DocumentRoot /home/demo1/public_html") != 3 {
		t.Fatalf("both.example must serve the site over HTTP and HTTPS:\n%s", got)
	}

	// A suspended account shows the notice over HTTPS too, without redirecting.
	s.Suspended = true
	if got := string(render(vhostTmpl, testWeb().data(s, false))); strings.Contains(got, "https://%{SERVER_NAME}") || strings.Count(got, "xcp-suspended/index.html") != 4 {
		t.Fatalf("suspended:\n%s", got)
	}
}

func TestCheckSiteTLS(t *testing.T) {
	good := testTLS(t, "a.example")
	other := testTLS(t, "b.example")
	bad := map[string]Vhost{
		"key of another certificate": {Name: "a.example", DocRoot: "public_html", TLS: &TLS{CertPEM: good.CertPEM, KeyPEM: other.KeyPEM}},
		"name not covered":           {Name: "a.example", DocRoot: "public_html", TLS: other},
		"force HTTPS without one":    {Name: "a.example", DocRoot: "public_html", ForceHTTPS: true},
		"not PEM":                    {Name: "a.example", DocRoot: "public_html", TLS: &TLS{CertPEM: "SSLCertificateFile /etc/shadow", KeyPEM: good.KeyPEM}},
	}
	for name, v := range bad {
		if err := CheckSite(Site{Username: "demo1", UID: 10000, Vhosts: []Vhost{v}}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	wild := Vhost{Name: "*.w.example", DocRoot: "public_html", TLS: testTLS(t, "*.w.example")}
	if err := CheckSite(Site{Username: "demo1", UID: 10000, Vhosts: []Vhost{{Name: "w.example", DocRoot: "public_html"}, wild}}); err != nil {
		t.Fatalf("wildcard certificate: %v", err)
	}
}

func TestCertFiles(t *testing.T) {
	w := testWeb()
	w.CertDir = t.TempDir()
	dir := filepath.Join(w.CertDir, "demo1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gone.example.crt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	tlsA := testTLS(t, "a.example")
	files, err := w.certFiles(Site{Username: "demo1", Vhosts: []Vhost{
		{Name: "a.example", TLS: tlsA}, {Name: "plain.example"}, {Name: "*.w.example", TLS: testTLS(t, "*.w.example")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, fmt.Sprintf("%s %v %v", f.name, f.content != nil, f.mode()))
	}
	want := []string{
		"a.example.crt true -rw-r--r--", "a.example.key true -rw-------",
		"_wildcard.w.example.crt true -rw-r--r--", "_wildcard.w.example.key true -rw-------",
		"gone.example.crt false -rw-r--r--",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("files =\n%q\nwant\n%q", got, want)
	}
	if string(files[0].content) != tlsA.CertPEM {
		t.Fatal("certificate not written as given (re-encoded PEM)")
	}
}

func TestCheckSite(t *testing.T) {
	if err := CheckSite(demoSite()); err != nil {
		t.Fatal(err)
	}
	one := func(v Vhost) Site { return Site{Username: "demo1", UID: 10000, Vhosts: []Vhost{v}} }
	web := func(name string) Vhost { return Vhost{Name: name, DocRoot: "public_html"} }
	redirect := func(r Redirect) Site {
		v := web("a.example")
		v.Redirects = []Redirect{r}
		return one(v)
	}
	tooMany := web("a.example")
	for i := range MaxVhostRedirects + 1 {
		tooMany.Redirects = append(tooMany.Redirects, Redirect{Path: fmt.Sprintf("/p%d", i), Target: "https://b.example/", Code: 301})
	}
	bad := map[string]Site{
		"no domains":         {Username: "demo1", UID: 10000},
		"unnormal domain":    one(web("Demo1.example")),
		"injection domain":   one(web("x.example\n    CustomLog \"|/bin/sh\" x")),
		"twice":              {Username: "demo1", UID: 10000, Vhosts: []Vhost{web("a.example"), web("a.example")}},
		"www served twice":   {Username: "demo1", UID: 10000, Vhosts: []Vhost{web("a.example"), web("www.a.example")}},
		"docroot outside":    one(Vhost{Name: "a.example", DocRoot: "../other/public_html"}),
		"docroot tmp":        one(Vhost{Name: "a.example", DocRoot: "tmp"}),
		"docroot unclean":    one(Vhost{Name: "a.example", DocRoot: "/public_html/"}),
		"docroot injection":  one(Vhost{Name: "a.example", DocRoot: "x>\n<Directory /"}),
		"bad canonical":      one(Vhost{Name: "a.example", DocRoot: "public_html", Canonical: "both"}),
		"wildcard canonical": one(Vhost{Name: "*.a.example", DocRoot: "public_html", Canonical: CanonicalWWW}),
		"target injection":   redirect(Redirect{Path: "/", Target: "https://b.example/\"\nCustomLog \"|/bin/sh\" x", Code: 301}),
		"target backref":     redirect(Redirect{Path: "/x", Target: "https://b.example/$1", Code: 301}),
		"path regex":         redirect(Redirect{Path: "/(.*)", Target: "https://b.example/", Code: 301}),
		"bad code":           redirect(Redirect{Path: "/", Target: "https://b.example/", Code: 200}),
		"keep with query":    redirect(Redirect{Path: "/", Target: "https://b.example/?a=1", Code: 301, KeepPath: true}),
		"too many redirects": one(tooMany),
		"bad php version":    {Username: "demo1", UID: 10000, Vhosts: []Vhost{web("a.example")}, PHPVersion: "8.3; rm"},
		"reserved username":  {Username: "root", UID: 10000, Vhosts: []Vhost{web("a.example")}},
		"too many children":  {Username: "demo1", UID: 10000, Vhosts: []Vhost{web("a.example")}, MaxChildren: 201},
	}
	dup := web("a.example")
	dup.Redirects = []Redirect{{Path: "/x", Target: "https://b.example/", Code: 301}, {Path: "/x", Target: "https://c.example/", Code: 302}}
	bad["two redirects for a path"] = one(dup)
	for name, s := range bad {
		if err := CheckSite(s); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(PHPFPMPaths()) != 16 || PHPFPMPaths()[0] != "/usr/sbin/php-fpm5.6" {
		t.Fatalf("php-fpm paths = %v", PHPFPMPaths())
	}
}
