package agent

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestHostCertificate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs chown (Linux)")
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := &HostCert{CertFile: filepath.Join(dir, "panel.crt"), KeyFile: filepath.Join(dir, "panel.key"), Group: g.Name}
	good := testTLS(t, "panel.example")

	if _, err := p.InstallCertificate("other.example", *good); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong name: %v", err)
	}
	p.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := p.InstallCertificate("panel.example", *good); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expired: %v", err)
	}
	p.Now = nil
	if changed, err := p.InstallCertificate("panel.example", *good); err != nil || !changed {
		t.Fatalf("install: %v %v", changed, err)
	}
	if b, _ := os.ReadFile(p.CertFile); string(b) != good.CertPEM {
		t.Fatal("certificate not written")
	}
	if fi, err := os.Stat(p.KeyFile); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("key file: %v %v", fi.Mode(), err)
	}
	if changed, err := p.InstallCertificate("panel.example", *good); err != nil || changed {
		t.Fatalf("same certificate again: %v %v", changed, err)
	}
}
