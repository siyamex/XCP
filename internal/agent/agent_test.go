package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var ctx = context.Background()

func TestServiceRegistry(t *testing.T) {
	r := NewServiceRegistry(UbuntuServices())
	ok := map[string]string{
		"web":         "apache2.service",
		"db":          "mariadb.service",
		"php-fpm@8.3": "php8.3-fpm.service",
		"php-fpm@7.4": "php7.4-fpm.service",
	}
	for id, want := range ok {
		if got, err := r.Unit(id); err != nil || got != want {
			t.Errorf("Unit(%q) = %q, %v; want %q", id, got, err, want)
		}
	}
	for _, bad := range []string{"", "sshd", "apache2.service", "php-fpm@8", "php-fpm@8.3; reboot", "php-fpm@../../x", "web "} {
		if _, err := r.Unit(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Unit(%q) err = %v, want ErrInvalidRequest", bad, err)
		}
	}
}

func TestParseShow(t *testing.T) {
	st, err := parseShow([]byte("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1234\nUnitFileState=enabled\n"))
	if err != nil || st != (UnitStatus{ActiveState: "active", SubState: "running", MainPID: 1234, Enabled: true}) {
		t.Fatalf("parseShow = %+v, %v", st, err)
	}
	st, err = parseShow([]byte("LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nUnitFileState=disabled\n"))
	if err != nil || st.Enabled || st.ActiveState != "inactive" {
		t.Fatalf("parseShow disabled = %+v, %v", st, err)
	}
	if _, err := parseShow([]byte("LoadState=not-found\nActiveState=inactive\n")); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("not-found err = %v", err)
	}
	if _, err := parseShow([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

type fakeManager struct {
	calls []string
	fail  string // unit whose actions fail
}

func (m *fakeManager) Status(_ context.Context, unit string) (UnitStatus, error) {
	m.calls = append(m.calls, "status "+unit)
	return UnitStatus{ActiveState: "active"}, nil
}

func (m *fakeManager) Do(_ context.Context, unit string, a Action) error {
	m.calls = append(m.calls, string(a)+" "+unit)
	if unit == m.fail {
		return errors.New(unit + " failed")
	}
	return nil
}

func TestServicesResolveBeforeCallingManager(t *testing.T) {
	m := &fakeManager{}
	s := Services{Registry: NewServiceRegistry(UbuntuServices()), Manager: m}
	if err := s.Do(ctx, "web", ActionReload); err != nil {
		t.Fatal(err)
	}
	if err := s.Do(ctx, "not-a-service", ActionRestart); err == nil {
		t.Fatal("unknown service accepted")
	}
	if len(m.calls) != 1 || m.calls[0] != "reload apache2.service" {
		t.Fatalf("calls = %v", m.calls)
	}
}

func newFiles(t *testing.T, check ConfigCheck) (*Files, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := NewFiles([]string{dir}, check)
	if err != nil {
		t.Fatal(err)
	}
	return f, dir
}

func TestFilesWriteAndRemove(t *testing.T) {
	f, dir := newFiles(t, nil)
	p := filepath.Join(dir, "vhosts", "alice.conf")

	changed, err := f.Write(ctx, p, []byte("v1"), 0o644, ValidatorNone)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits to compare
		changed, err = f.Write(ctx, p, []byte("v1"), 0o644, ValidatorNone)
		if err != nil || changed {
			t.Fatalf("identical write: changed=%v err=%v", changed, err)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != "v1" {
		t.Fatalf("content = %q", b)
	}
	if changed, err := f.Remove(ctx, p, ValidatorNone); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if changed, err := f.Remove(ctx, p, ValidatorNone); err != nil || changed {
		t.Fatalf("remove missing: changed=%v err=%v", changed, err)
	}
}

func TestFilesRejectBadRequests(t *testing.T) {
	f, dir := newFiles(t, nil)
	sep := string(filepath.Separator)
	bad := map[string]struct {
		path string
		mode os.FileMode
	}{
		"outside managed dir": {filepath.Join(filepath.Dir(dir), "x.conf"), 0o644},
		"the dir itself":      {dir, 0o644},
		"prefix trick":        {dir + "-evil" + sep + "x.conf", 0o644},
		"unclean":             {dir + sep + "a" + sep + ".." + sep + "x.conf", 0o644},
		"relative":            {"generated" + sep + "x.conf", 0o644},
		"hidden name":         {filepath.Join(dir, ".xcp-tmp-1"), 0o644},
		"space in name":       {filepath.Join(dir, "a b.conf"), 0o644},
		"world writable":      {filepath.Join(dir, "x.conf"), 0o666},
		"executable":          {filepath.Join(dir, "x.conf"), 0o755},
		"setuid":              {filepath.Join(dir, "x.conf"), 0o4644},
	}
	for name, tc := range bad {
		if _, err := f.Write(ctx, tc.path, []byte("x"), tc.mode, ValidatorNone); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	big := make([]byte, MaxManagedFileSize+1)
	if _, err := f.Write(ctx, filepath.Join(dir, "big.conf"), big, 0o644, ValidatorNone); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("oversized content: err = %v", err)
	}
	if _, err := f.Write(ctx, filepath.Join(dir, "x.conf"), []byte("x"), 0o644, ValidatorApache); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("validator without checker: err = %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Remove(ctx, filepath.Join(dir, "subdir"), ValidatorNone); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("remove directory: err = %v", err)
	}
}

func TestFilesRollBackWhenValidationFails(t *testing.T) {
	failing := func(context.Context, Validator) error {
		return &ValidationFailedError{Output: "Syntax error on line 3"}
	}
	f, dir := newFiles(t, failing)
	existing := filepath.Join(dir, "existing.conf")
	if err := os.WriteFile(existing, []byte("good"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := f.Write(ctx, existing, []byte("broken"), 0o644, ValidatorApache)
	var vf *ValidationFailedError
	if !errors.As(err, &vf) || !strings.Contains(vf.Output, "line 3") {
		t.Fatalf("err = %v, want ValidationFailedError", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "good" {
		t.Fatalf("previous content not restored: %q", b)
	}

	fresh := filepath.Join(dir, "new.conf")
	if _, err := f.Write(ctx, fresh, []byte("broken"), 0o644, ValidatorApache); !errors.As(err, &vf) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new file left behind after failed validation")
	}

	if _, err := f.Remove(ctx, existing, ValidatorApache); !errors.As(err, &vf) {
		t.Fatalf("remove err = %v", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "good" {
		t.Fatal("file not restored after failed removal validation")
	}
}

func TestCheckAccount(t *testing.T) {
	if err := CheckAccount("alice", 10000, "example.com"); err != nil {
		t.Fatal(err)
	}
	bad := map[string]struct {
		user   string
		uid    uint32
		domain string
	}{
		"reserved name":   {"root", 10000, ""},
		"bad name":        {"Alice", 10000, ""},
		"system uid":      {"alice", 999, ""},
		"uid too high":    {"alice", 60000, ""},
		"unnormal domain": {"alice", 10000, "Example.COM"},
		"bad domain":      {"alice", 10000, "exa mple.com"},
	}
	for name, tc := range bad {
		if err := CheckAccount(tc.user, tc.uid, tc.domain); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSliceBodyAndIndexPage(t *testing.T) {
	cpu, mem, tasks := uint32(150), uint64(512), uint32(64)
	got := sliceBody(Limits{CPUPercent: &cpu, MemoryMB: &mem, Tasks: &tasks})
	want := "[Slice]\nCPUQuota=150%\nMemoryMax=512M\nTasksMax=64\n"
	if got != want {
		t.Fatalf("sliceBody =\n%s\nwant\n%s", got, want)
	}
	if got := sliceBody(Limits{}); got != "[Slice]\n" {
		t.Fatalf("unlimited slice = %q", got)
	}
	if p := indexPage("<b>x</b>", "domains/<i>"); strings.Contains(p, "<b>x</b>") || strings.Contains(p, "<i>") {
		t.Fatalf("domain or folder not escaped: %s", p)
	}
	if p := indexPage("shop.example", "domains/shop.example"); !strings.Contains(p, "<code>domains/shop.example</code>") {
		t.Fatalf("placeholder must name its folder: %s", p)
	}
	if ShellNone.path() != "/usr/sbin/nologin" || ShellFull.path() != "/bin/bash" {
		t.Fatal("shell paths wrong")
	}
	if SliceName("alice") != "xcp-u-alice.slice" {
		t.Fatal("slice name")
	}
}
