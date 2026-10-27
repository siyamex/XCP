// Command xcp-install sets up XCP on a fresh Ubuntu 24.04 server.
// It is safe to run again: it upgrades binaries and keeps config, keys,
// certificate and data (see internal/install).
//
//	sudo ./xcp-install [--hostname panel.example.com] [--admin-user admin] [--dry-run]
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/siyamex/XCP/internal/install"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-install:", err)
		os.Exit(1)
	}
}

func run() error {
	exe, _ := os.Executable()
	host, _ := os.Hostname()
	from := flag.String("from", filepath.Dir(exe), "directory containing xcp-agent, xcp-api and xcpctl")
	hostname := flag.String("hostname", host, "server hostname, used in the panel URL and certificate")
	adminUser := flag.String("admin-user", "admin", "username of the first admin (only if no login exists)")
	pwStdin := flag.Bool("admin-password-stdin", false, "read the first admin's password from stdin instead of generating one")
	dryRun := flag.Bool("dry-run", false, "show what would change, change nothing")
	skipOS := flag.Bool("skip-os-check", false, "install on an OS other than Ubuntu 24.04 (unsupported)")
	flag.Parse()

	fmt.Printf("XCP installer %s\n\n", version.Version)
	if err := preflight(*dryRun, *skipOS); err != nil {
		return err
	}
	h, err := validate.Domain(*hostname)
	if err != nil {
		return fmt.Errorf("--hostname: %w (pass a fully qualified name like panel.example.com)", err)
	}
	if err := validate.Username(*adminUser); err != nil && *adminUser != "admin" && *adminUser != "root" {
		return fmt.Errorf("--admin-user: %w", err)
	}
	var password string
	if *pwStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
		if err := validate.Password(password); err != nil {
			return fmt.Errorf("admin password: %w", err)
		}
	}
	sys, err := install.NewLinuxSystem()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ips := serverIPs()
	res, err := install.Run(ctx, install.Options{
		Root: "/", BinDir: *from, Hostname: h, IPs: ips,
		AdminUser: *adminUser, AdminPassword: password, DryRun: *dryRun, Out: os.Stdout, Sys: sys,
	})
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("\nDry run: %d change(s) planned, nothing was changed.\n", len(res.Changed))
		return nil
	}

	fmt.Println("\nXCP is installed.")
	fmt.Printf("\n  Panel:     %s\n", res.URL)
	for _, ip := range ips {
		fmt.Printf("             https://%s:%d\n", formatHost(ip), install.PanelPort)
	}
	switch {
	case res.GeneratedPassword != "":
		fmt.Printf("  Username:  %s\n  Password:  %s\n", *adminUser, res.GeneratedPassword)
		fmt.Println("             (shown only now; you must change it at first login)")
	case res.AdminCreated:
		fmt.Printf("  Username:  %s (password as given)\n", *adminUser)
	default:
		fmt.Println("  Logins already existed; none were created.")
	}
	fmt.Println("\nThe panel certificate is self-signed, so browsers will warn until a")
	fmt.Println("real certificate is set up. Check this server any time with: sudo xcpctl doctor")
	return nil
}

func preflight(dryRun, skipOS bool) error {
	if runtime.GOOS != "linux" {
		return errors.New("xcp-install runs on Linux servers only")
	}
	if !dryRun && os.Geteuid() != 0 {
		return errors.New("run as root (sudo ./xcp-install)")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil && !dryRun {
		return errors.New("systemd is not running; XCP needs systemd")
	}
	if !skipOS {
		b, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return fmt.Errorf("cannot read /etc/os-release: %w", err)
		}
		id, ver := osField(string(b), "ID"), osField(string(b), "VERSION_ID")
		if id != "ubuntu" || ver != "24.04" {
			return fmt.Errorf("this is %s %s; supported now: Ubuntu 24.04 (use --skip-os-check to try anyway)", id, ver)
		}
	}
	return nil
}

func osField(osRelease, key string) string {
	for _, line := range strings.Split(osRelease, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// serverIPs lists global unicast addresses for the certificate and summary.
func serverIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() && !n.IP.IsLinkLocalUnicast() {
			out = append(out, n.IP.String())
		}
	}
	return out
}

func formatHost(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}
