package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/app"
	"github.com/siyamex/XCP/internal/config"
)

type checkResult struct {
	name, status, detail string
}

const (
	statusOK   = "OK"
	statusWarn = "WARN"
	statusFail = "FAIL"
)

func doctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to xcp.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	results := runChecks(*configPath)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	failed := 0
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.status, r.name, r.detail)
		if r.status == statusFail {
			failed++
		}
	}
	tw.Flush()
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func runChecks(configPath string) []checkResult {
	cfg, err := config.Load(configPath)
	if err != nil {
		return []checkResult{{"config", statusFail, err.Error()}}
	}
	res := []checkResult{
		{"config", statusOK, configPath},
		checkOS(),
		checkKeyFile(cfg.Paths.MasterKeyFile()),
	}
	if err := app.DropPrivileges(cfg.Agent.APIUser); err != nil {
		return append(res, checkResult{"service user", statusFail, err.Error()})
	}
	res = append(res, checkDatabase(configPath), checkAgent(cfg.Agent), checkAPI(cfg))
	return append(res, checkQuota(cfg.Paths.HomesRoot))
}

func checkOS() checkResult {
	if runtime.GOOS != "linux" {
		return checkResult{"os", statusWarn, runtime.GOOS + " (development machine; servers run Linux)"}
	}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return checkResult{"os", statusWarn, err.Error()}
	}
	osr := parseOSRelease(string(b))
	name := osr["PRETTY_NAME"]
	if osr["ID"] == "ubuntu" && osr["VERSION_ID"] == "24.04" {
		return checkResult{"os", statusOK, name}
	}
	return checkResult{"os", statusWarn, name + " (supported now: Ubuntu 24.04; more in P2)"}
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func checkKeyFile(path string) checkResult {
	fi, err := os.Stat(path)
	if err != nil {
		return checkResult{"master key", statusFail, err.Error()}
	}
	if fi.Size() != 32 {
		return checkResult{"master key", statusFail, fmt.Sprintf("%s has %d bytes, want 32", path, fi.Size())}
	}
	if runtime.GOOS == "linux" && fi.Mode().Perm()&0o007 != 0 {
		return checkResult{"master key", statusFail, fmt.Sprintf("%s is readable by everyone (mode %v); run: chmod 640 %s", path, fi.Mode().Perm(), path)}
	}
	return checkResult{"master key", statusOK, path}
}

func checkDatabase(configPath string) checkResult {
	a, err := app.Open(context.Background(), configPath)
	if err != nil {
		return checkResult{"database", statusFail, err.Error()}
	}
	defer a.Close()
	n, err := a.DB.CountLogins(context.Background())
	if err != nil {
		return checkResult{"database", statusFail, err.Error()}
	}
	if n == 0 {
		return checkResult{"database", statusWarn, "no logins yet; run: xcpctl admin create --username admin"}
	}
	return checkResult{"database", statusOK, fmt.Sprintf("%s (%d logins)", a.Cfg.DB.Path, n)}
}

func checkAgent(cfg config.Agent) checkResult {
	if cfg.Fake {
		return checkResult{"agent", statusWarn, "fake agent (agent.fake = true): development only"}
	}
	c, closer, err := agentrpc.Dial(cfg.Socket)
	if err != nil {
		return checkResult{"agent", statusFail, err.Error()}
	}
	defer closer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := c.Ping(ctx, &agentv1.PingRequest{})
	if err != nil {
		return checkResult{"agent", statusFail, fmt.Sprintf("%s: %v (is xcp-agent running?)", cfg.Socket, err)}
	}
	// A real write exercises the agent's safe file access (openat2) inside its
	// systemd sandbox, which a ping alone would not.
	const probe = "/etc/xcp/generated/doctor-probe"
	if _, err := c.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: probe, Content: []byte("ok\n"), Mode: 0o644}); err != nil {
		return checkResult{"agent", statusFail, fmt.Sprintf("xcp-agent %s answers, but cannot write files: %v", p.GetVersion(), err)}
	}
	if _, err := c.FileRemoveManaged(ctx, &agentv1.FileRemoveManagedRequest{Path: probe}); err != nil {
		return checkResult{"agent", statusFail, fmt.Sprintf("xcp-agent cannot remove files: %v", err)}
	}
	return checkResult{"agent", statusOK, fmt.Sprintf("xcp-agent %s on %s (file access OK)", p.GetVersion(), p.GetHostname())}
}

func checkAPI(cfg config.Config) checkResult {
	host, port, err := net.SplitHostPort(cfg.API.Listen)
	if err != nil {
		return checkResult{"api", statusFail, err.Error()}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "https"
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.API.InsecureDevHTTP {
		scheme = "http"
	} else if pem, err := os.ReadFile(cfg.API.TLSCert); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	url := scheme + "://" + net.JoinHostPort(host, port) + "/api/v1/health"
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := hc.Get(url)
	if err != nil {
		return checkResult{"api", statusFail, fmt.Sprintf("%s: %v (is xcp-api running?)", url, err)}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return checkResult{"api", statusFail, fmt.Sprintf("%s returned %s", url, resp.Status)}
	}
	return checkResult{"api", statusOK, url}
}

func checkQuota(homes string) checkResult {
	if runtime.GOOS != "linux" {
		return checkResult{"disk quotas", statusWarn, "not checked (not Linux)"}
	}
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return checkResult{"disk quotas", statusWarn, err.Error()}
	}
	mnt, opts, ok := mountFor(string(b), homes)
	if !ok {
		return checkResult{"disk quotas", statusWarn, "could not find the filesystem of " + homes}
	}
	for _, o := range []string{"usrquota", "usrjquota", "quota", "uquota", "uqnoenforce"} {
		if slices.ContainsFunc(opts, func(x string) bool { return x == o || strings.HasPrefix(x, o+"=") }) {
			return checkResult{"disk quotas", statusOK, fmt.Sprintf("enabled on %s", mnt)}
		}
	}
	return checkResult{"disk quotas", statusWarn, fmt.Sprintf("not enabled on %s (needed for disk limits from P1)", mnt)}
}

// mountFor returns the mount point and options of the filesystem holding dir,
// from /proc/mounts content (longest matching mount point wins).
func mountFor(mounts, dir string) (string, []string, bool) {
	dir = path.Clean(dir) // /proc/mounts paths are always Linux paths
	best, bestOpts := "", []string(nil)
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mp := strings.ReplaceAll(f[1], `\040`, " ")
		if (dir == mp || strings.HasPrefix(dir, strings.TrimSuffix(mp, "/")+"/")) && len(mp) >= len(best) {
			best, bestOpts = mp, strings.Split(f[3], ",")
		}
	}
	return best, bestOpts, best != ""
}
