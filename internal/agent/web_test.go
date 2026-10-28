package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testWeb() *Web {
	return &Web{
		HomesRoot: "/home", VhostDir: "/etc/apache2/xcp/vhosts", PHPDir: "/etc/php",
		SuspendedDir: "/var/www/xcp-suspended", LogDir: "/var/log/apache2/xcp", WebUser: "www-data",
	}
}

func TestVhostGolden(t *testing.T) {
	w := testWeb()
	got := string(render(vhostTmpl, w.data(Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example", "shop.example"}, PHPVersion: "8.3"})))
	want := `# Managed by XCP. Do not edit: changes are overwritten.
<VirtualHost *:80>
    ServerName demo1.example
    ServerAlias www.demo1.example shop.example www.shop.example
    DocumentRoot /home/demo1/public_html
    <Directory /home/demo1/public_html>
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

func TestSuspendedVhostServesNoticeOnly(t *testing.T) {
	got := string(render(vhostTmpl, testWeb().data(Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example"}, Suspended: true})))
	for _, must := range []string{`DocumentRoot /var/www/xcp-suspended`, `AliasMatch "^/.*$" "/var/www/xcp-suspended/index.html"`} {
		if !strings.Contains(got, must) {
			t.Errorf("suspended vhost lacks %q:\n%s", must, got)
		}
	}
	for _, mustNot := range []string{"public_html", "proxy:unix"} {
		if strings.Contains(got, mustNot) {
			t.Errorf("suspended vhost still serves the site (%q):\n%s", mustNot, got)
		}
	}
}

func TestPoolGolden(t *testing.T) {
	got := string(render(poolTmpl, testWeb().data(Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example"}, MaxChildren: 4, PHPVersion: "8.3"})))
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
	if def := string(render(poolTmpl, testWeb().data(Site{Username: "a", UID: 10000, Domains: []string{"a.example"}}))); !strings.Contains(def, "pm.max_children = 10") {
		t.Fatal("default max_children should be 10")
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

func TestCheckSite(t *testing.T) {
	ok := Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example"}, PHPVersion: "8.3"}
	if err := CheckSite(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Site{
		"no domains":        {Username: "demo1", UID: 10000},
		"unnormal domain":   {Username: "demo1", UID: 10000, Domains: []string{"Demo1.example"}},
		"injection domain":  {Username: "demo1", UID: 10000, Domains: []string{"x.example\n    CustomLog \"|/bin/sh\" x"}},
		"bad php version":   {Username: "demo1", UID: 10000, Domains: []string{"a.example"}, PHPVersion: "8.3; rm"},
		"reserved username": {Username: "root", UID: 10000, Domains: []string{"a.example"}},
		"too many children": {Username: "demo1", UID: 10000, Domains: []string{"a.example"}, MaxChildren: 201},
	}
	for name, s := range bad {
		if err := CheckSite(s); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(PHPFPMPaths()) != 16 || PHPFPMPaths()[0] != "/usr/sbin/php-fpm5.6" {
		t.Fatalf("php-fpm paths = %v", PHPFPMPaths())
	}
}
