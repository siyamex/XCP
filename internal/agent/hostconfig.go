package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// HostConfig changes the host's own settings (ADR-0016): its name, time
// zone, automatic OS updates, and reboots.
type HostConfig struct {
	Run        *execx.Runner
	HostsFile  string // /etc/hosts
	AptConfDir string // /etc/apt/apt.conf.d
	ZoneInfo   string // /usr/share/zoneinfo
}

// Paths of the host tools and files.
const (
	HostnamectlPath = "/usr/bin/hostnamectl"
	TimedatectlPath = "/usr/bin/timedatectl"
	HostsFile       = "/etc/hosts"
	AptConfDir      = "/etc/apt/apt.conf.d"
	ZoneInfoDir     = "/usr/share/zoneinfo"
	LocaltimeFile   = "/etc/localtime"
	rebootDelay     = "5s"
)

// SetHostname sets the host name and the 127.0.1.1 line of /etc/hosts.
func (h *HostConfig) SetHostname(ctx context.Context, name string) error {
	if n, err := validate.Domain(name); err != nil || n != name {
		return invalid("%q is not a normalised host name", name)
	}
	if _, err := h.Run.Run(ctx, execx.Cmd{Path: HostnamectlPath, Args: []string{"set-hostname", "--", name}}); err != nil {
		return err
	}
	root, err := fsx.OpenRoot(filepath.Dir(h.HostsFile))
	if err != nil {
		return err
	}
	defer root.Close()
	file := filepath.Base(h.HostsFile)
	old, err := root.ReadFile(file, 1<<20)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	short, _, _ := strings.Cut(name, ".")
	line := "127.0.1.1 " + name
	if short != name {
		line += " " + short
	}
	var out []string
	replaced := false
	for _, l := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		if strings.HasPrefix(l, "127.0.1.1") {
			if !replaced {
				out = append(out, line)
			}
			replaced = true
			continue
		}
		out = append(out, l)
	}
	if !replaced {
		out = append(out, line)
	}
	return root.WriteFileAtomic(file, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

var zoneRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+-]*(/[A-Za-z0-9][A-Za-z0-9_+-]*){0,2}$`)

// SetTimezone sets the system time zone to one of the tz database's.
func (h *HostConfig) SetTimezone(ctx context.Context, zone string) error {
	if len(zone) > 64 || !zoneRe.MatchString(zone) {
		return invalid("%q is not a time zone name like Europe/Berlin", zone)
	}
	fi, err := os.Stat(filepath.Join(h.ZoneInfo, filepath.FromSlash(zone)))
	if err != nil || !fi.Mode().IsRegular() {
		return invalid("%q is not a known time zone", zone)
	}
	_, err = h.Run.Run(ctx, execx.Cmd{Path: TimedatectlPath, Args: []string{"set-timezone", "--", zone}})
	return err
}

// SetOSUpdates turns Ubuntu's automatic security updates on or off. It
// reports whether the setting changed.
func (h *HostConfig) SetOSUpdates(_ context.Context, on bool) (bool, error) {
	v := "0"
	if on {
		v = "1"
	}
	content := "// Managed by XCP (ADR-0016). Changes are overwritten.\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"" + v + "\";\n"
	return writeFile(h.AptConfDir, "20auto-upgrades", content, 0o644, "")
}

// Reboot restarts the server in a few seconds, so the call can answer
// first: gracefully through systemd, or forced (no service shutdown).
func (h *HostConfig) Reboot(ctx context.Context, force bool) error {
	args := []string{"--on-active=" + rebootDelay, "--unit=xcp-reboot", "--collect", "--quiet", "--", "/usr/bin/systemctl", "reboot"}
	if force {
		args = append(args, "--force")
	}
	if _, err := h.Run.Run(ctx, execx.Cmd{Path: SystemdRunPath, Args: args}); err != nil {
		return fmt.Errorf("schedule the reboot: %w", err)
	}
	return nil
}

// timezoneName names the zone /etc/localtime points to.
func timezoneName(localtime string) string {
	if localtime == "" {
		return ""
	}
	target, err := os.Readlink(localtime)
	if err != nil {
		return ""
	}
	if _, zone, ok := strings.Cut(filepath.ToSlash(target), "zoneinfo/"); ok {
		return zone
	}
	return ""
}
