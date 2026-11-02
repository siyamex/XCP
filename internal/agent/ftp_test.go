package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/pwhash"
)

func TestCheckFTPAccount(t *testing.T) {
	h := pwhash.Hash("pw")
	ok := FTPAccount{Username: "alice", Logins: []FTPLogin{
		{Login: "web@alice.example", PasswordHash: h, Dir: "public_html", QuotaMB: 10},
		{Login: "a.b-c_d@xn--bcher-kva.example", PasswordHash: h, Dir: "."},
	}}
	if err := CheckFTPAccount(ok); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]FTPLogin{
		"no domain":      {Login: "web", PasswordHash: h, Dir: "."},
		"upper case":     {Login: "Web@alice.example", PasswordHash: h, Dir: "."},
		"wildcard":       {Login: "web@*.alice.example", PasswordHash: h, Dir: "."},
		"leading dot":    {Login: ".web@alice.example", PasswordHash: h, Dir: "."},
		"double dot":     {Login: "w..b@alice.example", PasswordHash: h, Dir: "."},
		"plain password": {Login: "web@alice.example", PasswordHash: "pw", Dir: "."},
		"leaves home":    {Login: "web@alice.example", PasswordHash: h, Dir: "../bob"},
		"absolute":       {Login: "web@alice.example", PasswordHash: h, Dir: "/etc"},
		"unclean":        {Login: "web@alice.example", PasswordHash: h, Dir: "a//b/"},
		"empty folder":   {Login: "web@alice.example", PasswordHash: h, Dir: ""},
		"negative quota": {Login: "web@alice.example", PasswordHash: h, Dir: ".", QuotaMB: -1},
	} {
		a := FTPAccount{Username: "alice", Logins: []FTPLogin{l}}
		if err := CheckFTPAccount(a); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	twice := FTPAccount{Username: "alice", Logins: []FTPLogin{ok.Logins[0], ok.Logins[0]}}
	if err := CheckFTPAccount(twice); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("a login twice: %v", err)
	}
}

func TestFTPConfig(t *testing.T) {
	c := FTPConfig("/etc/xcp/ssl/hostname.crt", "/etc/xcp/ssl/hostname.key")
	for _, want := range []string{
		"ExtAuth " + FTPAuthSocket + "\n", "ChrootEveryone yes\n", "NoAnonymous yes\n", "MinUID 10000\n",
		"PassivePortRange 30000 30999\n", "TLS 1\n", `CertFileAndKey "/etc/xcp/ssl/hostname.crt" "/etc/xcp/ssl/hostname.key"` + "\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"PAMAuthentication", "UnixAuthentication", "PureDB"} {
		if strings.Contains(c, bad) {
			t.Errorf("%s: system logins must stay off", bad)
		}
	}
}

func TestFTPFoldersAreMadeInsideTheHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ownership needs Linux")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := fsx.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, dir := range []string{"public_html/shop/new", "."} {
		if err := folder(root, dir, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(filepath.Join(home, "public_html/shop/new")); err != nil || !fi.IsDir() {
		t.Fatalf("folder not made: %v", err)
	}
	for _, dir := range []string{"file", "file/sub", "link", "link/sub"} {
		if err := folder(root, dir, os.Getuid(), os.Getgid()); err == nil {
			t.Errorf("%s: made through a file or symlink", dir)
		}
	}
	if _, err := os.Stat("/etc/sub"); err == nil {
		t.Fatal("a folder was made outside the home")
	}
}
