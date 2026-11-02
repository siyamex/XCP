package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/siyamex/XCP/internal/agent"
)

type fakeSys struct {
	userExists bool
	admins     int
	calls      []string
	healthCA   []byte
	adminPW    string
	mustChange bool
	webDone    bool
	webErr     error
	dnsDone    bool
	dbDone     bool
	mailDone   bool
	ftpDone    bool
	tarball    []byte // what Download returns
}

func (f *fakeSys) InstallDatabaseServer(context.Context) (bool, error) {
	f.calls = append(f.calls, "db install")
	installed := !f.dbDone
	f.dbDone = true
	return installed, nil
}

func (f *fakeSys) InstallMailServer(context.Context) (bool, error) {
	f.calls = append(f.calls, "mail install")
	installed := !f.mailDone
	f.mailDone = true
	return installed, nil
}

func (f *fakeSys) InstallBase(context.Context) (bool, error) {
	f.calls = append(f.calls, "base install")
	return false, nil
}

func (f *fakeSys) InstallFTPServer(context.Context) (bool, error) {
	f.calls = append(f.calls, "ftp install")
	installed := !f.ftpDone
	f.ftpDone = true
	return installed, nil
}

func (f *fakeSys) UpdateRoundcubeDB(context.Context) error {
	f.calls = append(f.calls, "roundcube updatedb")
	return nil
}

func (f *fakeSys) PHPFPMVersions() []string { return []string{"8.4", "8.3", "7.4"} }

func (f *fakeSys) Download(_ context.Context, url string, _ int64) ([]byte, error) {
	f.calls = append(f.calls, "download "+url)
	return f.tarball, nil
}

// releaseTarball builds a phpMyAdmin-like release with the given files.
func releaseTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(files[name]))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// useRelease makes the installer expect this tarball as the pinned release.
func useRelease(t *testing.T, data []byte) {
	t.Helper()
	saved := phpMyAdmin
	sum := sha256.Sum256(data)
	savedRC := roundcube
	phpMyAdmin.Version, phpMyAdmin.URL, phpMyAdmin.SHA256 = "test", "https://files.example/pma.tar.gz", hex.EncodeToString(sum[:])
	roundcube.Version, roundcube.URL, roundcube.SHA256 = "test", "https://files.example/rc.tar.gz", hex.EncodeToString(sum[:])
	t.Cleanup(func() { phpMyAdmin, roundcube = saved, savedRC })
}

func (f *fakeSys) EnsureSystemUser(_ context.Context, name, _ string) (bool, error) {
	f.calls = append(f.calls, "useradd "+name)
	created := !f.userExists
	f.userExists = true
	return created, nil
}

func (f *fakeSys) LookupIDs(string) (int, int, error) {
	if !f.userExists {
		return -1, -1, os.ErrNotExist
	}
	return 990, 990, nil
}

func (f *fakeSys) LookupGroup(string) (int, error) { return 4, nil }

func (f *fakeSys) Chown(string, int, int) error { return nil }

func (f *fakeSys) Systemctl(_ context.Context, args ...string) error {
	f.calls = append(f.calls, "systemctl "+strings.Join(args, " "))
	return nil
}

func (f *fakeSys) CreateFirstAdmin(_ context.Context, user, pw string, mustChange bool) (bool, error) {
	f.calls = append(f.calls, "admin "+user)
	if f.admins > 0 {
		return false, nil
	}
	f.admins++
	f.adminPW, f.mustChange = pw, mustChange
	return true, nil
}

func (f *fakeSys) InstallWebStack(context.Context) (bool, error) {
	f.calls = append(f.calls, "web install")
	if f.webErr != nil {
		return false, f.webErr
	}
	installed := !f.webDone
	f.webDone = true
	return installed, nil
}

func (f *fakeSys) EnableApacheSite(context.Context) error {
	f.calls = append(f.calls, "a2ensite xcp")
	return nil
}

func (f *fakeSys) InstallDNSServer(context.Context) (bool, error) {
	f.calls = append(f.calls, "dns install")
	installed := !f.dnsDone
	f.dnsDone = true
	return installed, nil
}

func (f *fakeSys) PDNSSchema() ([]byte, error) {
	return []byte("CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT NOT NULL);"), nil
}

func (f *fakeSys) WaitHealthy(_ context.Context, _ string, ca []byte) error {
	f.calls = append(f.calls, "health")
	f.healthCA = ca
	return nil
}

type env struct {
	root, bin string
	sys       *fakeSys
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{root: t.TempDir(), bin: t.TempDir(), sys: &fakeSys{tarball: releaseTarball(t, map[string]string{
		"phpMyAdmin-test/index.php": "<?php // pma", "phpMyAdmin-test/setup/index.php": "<?php // setup",
		"phpMyAdmin-test/js/app.js": "app",
		// Roundcube's parts, so one tarball serves as both releases.
		"phpMyAdmin-test/public_html/index.php": "<?php // rc", "phpMyAdmin-test/SQL/sqlite.initial.sql": "CREATE TABLE users (user_id INTEGER);",
		"phpMyAdmin-test/plugins/autologon/autologon.php": "<?php",
	})}}
	useRelease(t, e.sys.tarball)
	for name := range Binaries {
		writeBin(t, e, name, "v1")
	}
	return e
}

func writeBin(t *testing.T, e *env, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.bin, name), []byte(name+" "+content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (e *env) run(t *testing.T, dry bool) *Result {
	t.Helper()
	e.sys.calls = nil
	res, err := Run(context.Background(), Options{
		Root: e.root, BinDir: e.bin, Hostname: "panel.example.com", IPs: []string{"203.0.113.5"},
		AdminUser: "admin", DryRun: dry, Out: io.Discard, Sys: e.sys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (e *env) read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, filepath.FromSlash(p)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFirstInstall(t *testing.T) {
	e := newEnv(t)
	res := e.run(t, false)

	if res.URL != "https://panel.example.com:2443" || !res.AdminCreated || len(res.GeneratedPassword) != 20 {
		t.Fatalf("result = %+v", res)
	}
	if e.sys.adminPW != res.GeneratedPassword || !e.sys.mustChange {
		t.Fatal("generated admin password must be passed through and require a change at first login")
	}
	for name, dst := range Binaries {
		if got := string(e.read(t, dst)); got != name+" v1" {
			t.Errorf("%s = %q", dst, got)
		}
	}
	if !strings.Contains(string(e.read(t, ApacheConf)), "IncludeOptional /etc/apache2/xcp/vhosts/*.conf") {
		t.Error("Apache include for the per-account virtual hosts not written")
	}
	key := strings.TrimSpace(string(e.read(t, PDNSKeyFile)))
	pdns := string(e.read(t, PDNSConf))
	for _, want := range []string{"launch=gsqlite3\n", "api-key=" + key + "\n", "local-address=127.0.0.1, ::1, 203.0.113.5\n", "webserver-address=127.0.0.1\n"} {
		if len(key) != 64 || !strings.Contains(pdns, want) {
			t.Errorf("PowerDNS config lacks %q (key %q):\n%s", want, key, pdns)
		}
	}
	// phpMyAdmin: the release without its setup wizard, sign-on only, its own pool on PHP 8.3.
	if got := string(e.read(t, PMADir+"/index.php")); got != "<?php // pma" {
		t.Errorf("phpMyAdmin not unpacked: %q", got)
	}
	if _, err := os.Stat(filepath.Join(e.root, filepath.FromSlash(PMADir+"/setup"))); !errors.Is(err, os.ErrNotExist) {
		t.Error("phpMyAdmin's setup wizard was kept")
	}
	pmaCfg := string(e.read(t, PMAConfigDir+"/config.inc.php"))
	for _, want := range []string{"'auth_type'] = 'signon'", "'AllowRoot'] = false", "sodium_hex2bin('"} {
		if !strings.Contains(pmaCfg, want) {
			t.Errorf("phpMyAdmin config lacks %q", want)
		}
	}
	if !strings.Contains(string(e.read(t, PMADir+"/xcp-signon.php")), "/var/lib/xcp-phpmyadmin/tickets/") {
		t.Error("sign-on script not written")
	}
	if !strings.Contains(string(e.read(t, "/etc/php/8.3/fpm/pool.d/xcp_phpmyadmin.conf")), "user = xcp-pma") {
		t.Error("phpMyAdmin pool not written for PHP 8.3")
	}
	apache := string(e.read(t, ApacheConf))
	for _, want := range []string{"Alias /phpmyadmin " + PMADir, "<IfFile " + HostCertFile + ">", `RequestHeader edit* Cookie "(^|;\s*)(__Host-)?xcp_session=[^;]*" ""`} {
		if !strings.Contains(apache, want) {
			t.Errorf("Apache site lacks %q:\n%s", want, apache)
		}
	}
	mainCF := string(e.read(t, "/etc/postfix/main.cf"))
	for _, want := range []string{"myhostname = panel.example.com\n", "virtual_mailbox_maps = texthash:/etc/postfix/xcp/mailboxes\n", "smtpd_tls_cert_file = /etc/xcp/ssl/panel.crt\n"} {
		if !strings.Contains(mainCF, want) {
			t.Errorf("main.cf lacks %q", want)
		}
	}
	// Roundcube: its database from its schema, sign-on only through our plugin, the sample one gone.
	if db := e.read(t, "/var/lib/xcp-roundcube/db/roundcube.db"); !bytes.HasPrefix(db, []byte("SQLite format 3")) {
		t.Error("Roundcube's database not created")
	}
	if !strings.Contains(string(e.read(t, RCDir+"/plugins/xcp_sso/xcp_sso.php")), "/var/lib/xcp-roundcube/tickets/") ||
		!strings.Contains(string(e.read(t, RCDir+"/config/config.inc.php")), "'xcp_sso'") {
		t.Error("Roundcube sign-on not set up")
	}
	if _, err := os.Stat(filepath.Join(e.root, filepath.FromSlash(RCDir+"/plugins/autologon"))); !errors.Is(err, os.ErrNotExist) {
		t.Error("Roundcube's sample autologon plugin was kept")
	}
	if !strings.Contains(string(e.read(t, ApacheConf)), "Alias /webmail "+RCDir+"/public_html") {
		t.Error("webmail not served")
	}
	if !strings.Contains(string(e.read(t, DovecotConf)), "sieve_before = /etc/dovecot/xcp/sieve/%d/%n.sieve") {
		t.Error("autoresponders not set up in Dovecot")
	}
	if _, err := os.Stat(filepath.Join(e.root, "etc", "postfix", "xcp", "aliases")); err != nil {
		t.Error("empty Postfix maps not created")
	}
	if !strings.Contains(string(e.read(t, MariaDBConf)), "bind-address = 127.0.0.1") {
		t.Error("MariaDB not bound to localhost")
	}
	if db := e.read(t, PDNSDatabase); !bytes.HasPrefix(db, []byte("SQLite format 3")) {
		t.Error("PowerDNS database not created")
	}
	cfg := string(e.read(t, ConfigFile))
	for _, want := range []string{`listen = ":2443"`, `api_user = "xcp"`, `path = "/var/lib/xcp/xcp.db"`, `tls_cert = "/etc/xcp/ssl/panel.crt"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %s:\n%s", want, cfg)
		}
	}
	if key := e.read(t, SecretsDir+"/master.key"); len(key) != 32 {
		t.Errorf("master key is %d bytes", len(key))
	}
	block, _ := pem.Decode(e.read(t, CertFile))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"panel.example.com", "localhost", "127.0.0.1", "203.0.113.5"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Errorf("certificate not valid for %s: %v", host, err)
		}
	}
	if !bytes.Equal(e.sys.healthCA, e.read(t, CertFile)) {
		t.Error("health check must pin the generated certificate")
	}
	for _, u := range []string{"xcp-agent.service", "xcp-api.service"} {
		if !strings.Contains(string(e.read(t, UnitDir+"/"+u)), "ExecStart=/usr/sbin/") {
			t.Errorf("unit %s not written", u)
		}
	}
	want := []string{
		"useradd xcp", "base install", "systemctl daemon-reload", "systemctl enable --now xcp-agent.service xcp-api.service xcp-logd.service",
		"systemctl restart xcp-agent.service xcp-api.service xcp-logd.service", "health", "web install", "a2ensite xcp",
		"dns install", "systemctl enable --now pdns.service", "systemctl restart pdns.service",
		"db install", "systemctl restart mariadb.service", "useradd xcp-pma", "download https://files.example/pma.tar.gz",
		"systemctl reload-or-restart php8.3-fpm.service", "systemctl reload-or-restart apache2.service",
		"mail install", "systemctl enable --now redis-server.service rspamd.service dovecot.service postfix.service",
		"systemctl restart rspamd.service", "systemctl restart dovecot.service", "systemctl restart postfix.service",
		"useradd xcp-rc", "download https://files.example/rc.tar.gz",
		"systemctl reload-or-restart php8.3-fpm.service", "systemctl reload-or-restart apache2.service",
		"ftp install", "systemctl daemon-reload", "systemctl enable --now xcp-ftpauth.service pure-ftpd.service",
		"systemctl restart xcp-ftpauth.service", "systemctl restart pure-ftpd.service",
		"admin admin",
	}
	if !slices.Equal(e.sys.calls, want) {
		t.Fatalf("calls =\n%q\nwant\n%q", e.sys.calls, want)
	}
	if c := string(e.read(t, agent.FTPConfFile)); !strings.Contains(c, "ExtAuth "+agent.FTPAuthSocket) || !strings.Contains(c, `CertFileAndKey "`+CertFile+`"`) {
		t.Errorf("Pure-FTPd configuration:\n%s", c)
	}
	if u := string(e.read(t, UnitDir+"/"+FTPUnit)); !strings.Contains(u, "ExecStart=/usr/sbin/pure-ftpd "+agent.FTPConfFile) {
		t.Errorf("pure-ftpd unit:\n%s", u)
	}
}

func TestReinstallChangesNothingAndKeepsEdits(t *testing.T) {
	e := newEnv(t)
	first := e.run(t, false)
	key := e.read(t, SecretsDir+"/master.key")
	pdnsKey := e.read(t, PDNSKeyFile)
	cert := e.read(t, CertFile)
	edited := append(e.read(t, ConfigFile), []byte("\n# my edit\n")...)
	os.WriteFile(filepath.Join(e.root, filepath.FromSlash(ConfigFile)), edited, 0o644)

	res := e.run(t, false)
	if len(res.Changed) != 0 || res.AdminCreated || res.GeneratedPassword != "" {
		t.Fatalf("second run changed %v (admin=%v)", res.Changed, res.AdminCreated)
	}
	if !bytes.Equal(e.read(t, ConfigFile), edited) {
		t.Error("admin's config edits were overwritten")
	}
	if !bytes.Equal(e.read(t, SecretsDir+"/master.key"), key) || !bytes.Equal(e.read(t, CertFile), cert) {
		t.Fatal("master key or certificate was replaced: this would lock out encrypted secrets / break pinning")
	}
	if slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service xcp-logd.service") || slices.Contains(e.sys.calls, "systemctl daemon-reload") ||
		slices.Contains(e.sys.calls, "systemctl restart pdns.service") || slices.Contains(e.sys.calls, "systemctl restart mariadb.service") ||
		slices.Contains(e.sys.calls, "systemctl reload-or-restart apache2.service") || slices.Contains(e.sys.calls, "systemctl restart postfix.service") {
		t.Fatalf("services restarted although nothing changed: %q", e.sys.calls)
	}
	if !bytes.Equal(e.read(t, PDNSKeyFile), pdnsKey) {
		t.Fatal("PowerDNS API key replaced: the agent would lose access")
	}
	_ = first
}

func TestUpgradeRestartsServices(t *testing.T) {
	e := newEnv(t)
	e.run(t, false)
	writeBin(t, e, "xcp-api", "v2")
	res := e.run(t, false)
	if !slices.Equal(res.Changed, []string{"file /usr/sbin/xcp-api"}) {
		t.Fatalf("changed = %v", res.Changed)
	}
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service xcp-logd.service") {
		t.Fatalf("no restart after binary upgrade: %q", e.sys.calls)
	}
	if string(e.read(t, "/usr/sbin/xcp-api")) != "xcp-api v2" {
		t.Fatal("binary not upgraded")
	}
}

func TestWebFailureAfterUpgradeStillRestarts(t *testing.T) {
	e := newEnv(t)
	e.run(t, false)
	writeBin(t, e, "xcp-api", "v2")
	e.sys.webErr, e.sys.calls = errors.New("apt-get update: network down"), nil
	_, err := Run(context.Background(), Options{
		Root: e.root, BinDir: e.bin, Hostname: "panel.example.com", AdminUser: "admin", Out: io.Discard, Sys: e.sys,
	})
	if err == nil {
		t.Fatal("web failure not reported")
	}
	// A re-run finds the binaries unchanged, so this is the only chance to restart.
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service xcp-logd.service") {
		t.Fatalf("old binaries left running after a failed web step: %q", e.sys.calls)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	e := newEnv(t)
	res := e.run(t, true)
	if len(res.Changed) < 10 {
		t.Fatalf("dry run should list the planned changes, got %v", res.Changed)
	}
	entries, _ := os.ReadDir(e.root)
	if len(entries) != 0 {
		t.Fatalf("dry run created files: %v", entries)
	}
	for _, c := range e.sys.calls {
		if c != "" {
			t.Fatalf("dry run made a system call: %q", e.sys.calls)
		}
	}
}

func TestMissingKeyRegeneratesCertificatePair(t *testing.T) {
	e := newEnv(t)
	e.run(t, false)
	oldCert := e.read(t, CertFile)
	os.Remove(filepath.Join(e.root, filepath.FromSlash(KeyFile)))
	e.run(t, false)
	if len(e.read(t, KeyFile)) == 0 || bytes.Equal(e.read(t, CertFile), oldCert) {
		t.Fatal("a lost key must produce a new certificate and key pair")
	}
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service xcp-logd.service") {
		t.Fatal("xcp-api must restart to load the new certificate")
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p := GeneratePassword()
		if len(p) != 20 || strings.ContainsAny(p, "0O1lI") || seen[p] {
			t.Fatalf("bad password %q", p)
		}
		seen[p] = true
	}
}

func TestPHPMyAdminReleaseChecks(t *testing.T) {
	e := newEnv(t)
	e.sys.tarball = append(slices.Clone(e.sys.tarball), 0) // not the pinned release
	_, err := Run(context.Background(), Options{
		Root: e.root, BinDir: e.bin, Hostname: "panel.example.com", AdminUser: "admin", Out: io.Discard, Sys: e.sys,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("a download with the wrong hash was installed: %v", err)
	}
	if err := extractTarGz(releaseTarball(t, map[string]string{"top/../../escape.php": "x"}), t.TempDir()); err == nil {
		t.Fatal("an entry leaving the folder was unpacked")
	}
}

func TestPMAPHP(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"8.4", "8.3", "7.4"}, "8.3"},
		{[]string{"8.1", "8.10"}, "8.1"},
		{[]string{"8.4"}, "8.4"},
		{nil, ""},
	} {
		if got := pmaPHP(c.in); got != c.want {
			t.Errorf("pmaPHP(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRoundcubeUpgradeUpdatesItsDatabase(t *testing.T) {
	e := newEnv(t)
	e.run(t, false)
	if slices.Contains(e.sys.calls, "roundcube updatedb") {
		t.Fatal("a new install has nothing to update")
	}
	// A new release: same tree, another version.
	saved := roundcube
	roundcube.Version = "test2"
	t.Cleanup(func() { roundcube = saved })
	e.run(t, false)
	if !slices.Contains(e.sys.calls, "roundcube updatedb") {
		t.Fatalf("upgrade did not update Roundcube's database: %q", e.sys.calls)
	}
	e.run(t, false)
	if slices.Contains(e.sys.calls, "roundcube updatedb") {
		t.Fatal("updated again although nothing changed")
	}
}
