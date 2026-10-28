package install

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
	e := &env{root: t.TempDir(), bin: t.TempDir(), sys: &fakeSys{}}
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
		"useradd xcp", "systemctl daemon-reload", "systemctl enable --now xcp-agent.service xcp-api.service",
		"systemctl restart xcp-agent.service xcp-api.service", "health", "web install", "a2ensite xcp", "admin admin",
	}
	if !slices.Equal(e.sys.calls, want) {
		t.Fatalf("calls =\n%q\nwant\n%q", e.sys.calls, want)
	}
}

func TestReinstallChangesNothingAndKeepsEdits(t *testing.T) {
	e := newEnv(t)
	first := e.run(t, false)
	key := e.read(t, SecretsDir+"/master.key")
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
	if slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service") || slices.Contains(e.sys.calls, "systemctl daemon-reload") {
		t.Fatalf("services restarted although nothing changed: %q", e.sys.calls)
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
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service") {
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
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service") {
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
	if !slices.Contains(e.sys.calls, "systemctl restart xcp-agent.service xcp-api.service") {
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
