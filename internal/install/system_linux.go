//go:build linux

package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/execx"
)

// Programs the installer runs.
const (
	useraddPath   = "/usr/sbin/useradd"
	systemctlPath = "/usr/bin/systemctl"
	xcpctlPath    = "/usr/bin/xcpctl"
	aptGetPath    = "/usr/bin/apt-get"
	a2enmodPath   = "/usr/sbin/a2enmod"
	a2enconfPath  = "/usr/sbin/a2enconf"
)

// LinuxSystem is the real System for Ubuntu/Debian.
type LinuxSystem struct {
	run *execx.Runner
}

// NewLinuxSystem returns the production System.
func NewLinuxSystem() (*LinuxSystem, error) {
	r, err := execx.NewRunner(useraddPath, systemctlPath, xcpctlPath, aptGetPath, a2enmodPath, a2enconfPath)
	if err != nil {
		return nil, err
	}
	return &LinuxSystem{run: r}, nil
}

// EnsureSystemUser implements System.
func (s *LinuxSystem) EnsureSystemUser(ctx context.Context, name, home string) (bool, error) {
	if _, err := user.Lookup(name); err == nil {
		return false, nil
	}
	_, err := s.run.Run(ctx, execx.Cmd{Path: useraddPath, Args: []string{
		"--system", "--user-group", "--no-create-home", "--home-dir", home,
		"--shell", "/usr/sbin/nologin", "--comment", "XCP panel", "--", name,
	}})
	return err == nil, err
}

// LookupIDs implements System.
func (s *LinuxSystem) LookupIDs(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return -1, -1, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	return uid, gid, errors.Join(err1, err2)
}

// Chown implements System. It never follows symlinks.
func (s *LinuxSystem) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

// Systemctl implements System.
func (s *LinuxSystem) Systemctl(ctx context.Context, args ...string) error {
	_, err := s.run.Run(ctx, execx.Cmd{Path: systemctlPath, Args: args, Timeout: 2 * time.Minute})
	return err
}

// CreateFirstAdmin implements System via `xcpctl admin create --if-none`,
// which switches to the service user before touching the database.
func (s *LinuxSystem) CreateFirstAdmin(ctx context.Context, username, password string, mustChange bool) (bool, error) {
	args := []string{"admin", "create", "--config", ConfigFile, "--username", username, "--if-none"}
	if mustChange {
		args = append(args, "--must-change")
	}
	res, err := s.run.Run(ctx, execx.Cmd{Path: xcpctlPath, Args: args, Stdin: strings.NewReader(password + "\n")})
	if err != nil {
		return false, err
	}
	return strings.Contains(string(res.Stdout), "created admin login"), nil
}

// WaitHealthy implements System: it polls the health URL for up to a minute.
func (s *LinuxSystem) WaitHealthy(ctx context.Context, url string, caPEM []byte) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("panel certificate is not valid PEM")
	}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}}
	deadline := time.Now().Add(time.Minute)
	var last error
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("status %s", resp.Status)
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("xcp-api did not become healthy at %s: %w (see: journalctl -u xcp-api)", url, last)
}

// webStackInstalled reports whether Apache and at least one PHP-FPM exist.
func webStackInstalled() bool {
	if _, err := os.Stat("/usr/sbin/apachectl"); err != nil {
		return false
	}
	m, _ := filepath.Glob("/usr/sbin/php-fpm[0-9]*")
	return len(m) > 0
}

// InstallWebStack implements System.
func (s *LinuxSystem) InstallWebStack(ctx context.Context) (bool, error) {
	installed := false
	if !webStackInstalled() {
		env := append(slices.Clone(execx.SafeEnv), "DEBIAN_FRONTEND=noninteractive")
		if _, err := s.run.Run(ctx, execx.Cmd{Path: aptGetPath, Args: []string{"update", "-q"}, Env: env, Timeout: 10 * time.Minute}); err != nil {
			return false, fmt.Errorf("apt-get update: %w", err)
		}
		if _, err := s.run.Run(ctx, execx.Cmd{
			Path: aptGetPath, Args: []string{"install", "-y", "-q", "--no-install-recommends", "apache2", "php-fpm"},
			Env: env, Timeout: 20 * time.Minute,
		}); err != nil {
			return false, fmt.Errorf("apt-get install apache2 php-fpm: %w", err)
		}
		installed = true
	}
	if _, err := s.run.Run(ctx, execx.Cmd{Path: a2enmodPath, Args: []string{"-q", "proxy_fcgi", "setenvif", "rewrite", "headers"}}); err != nil {
		return installed, fmt.Errorf("a2enmod: %w", err)
	}
	return installed, nil
}

// EnableApacheConf implements System.
func (s *LinuxSystem) EnableApacheConf(ctx context.Context) error {
	if _, err := s.run.Run(ctx, execx.Cmd{Path: a2enconfPath, Args: []string{"-q", "xcp"}}); err != nil {
		return fmt.Errorf("a2enconf xcp: %w", err)
	}
	if err := s.Systemctl(ctx, "enable", "--now", "apache2.service"); err != nil {
		return err
	}
	return s.Systemctl(ctx, "reload-or-restart", "apache2.service")
}
