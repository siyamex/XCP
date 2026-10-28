package agent

import (
	"errors"
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
	got := string(render(vhostTmpl, w.data(Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example", "shop.example"}})))
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
        SetHandler "proxy:unix:/run/php/xcp-demo1.sock|fcgi://localhost"
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
	got := string(render(poolTmpl, testWeb().data(Site{Username: "demo1", UID: 10000, Domains: []string{"demo1.example"}, MaxChildren: 4})))
	want := `; Managed by XCP. Do not edit: changes are overwritten.
[xcp-demo1]
user = demo1
group = demo1
listen = /run/php/xcp-demo1.sock
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
