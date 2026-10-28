// Package agent implements xcp-agent's privileged operations. It has no
// transport code: internal/agentrpc exposes it over gRPC. Every function
// here re-validates its input, because callers are not trusted.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/siyamex/XCP/internal/execx"
)

// ErrInvalidRequest means the caller sent a value the agent refuses.
var ErrInvalidRequest = errors.New("invalid request")

// ErrNotInstalled means the service's unit does not exist on this server.
var ErrNotInstalled = errors.New("service not installed")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}

// UbuntuServices maps logical service IDs to systemd units on Ubuntu/Debian.
// Other OS drivers will provide their own map (01-architecture.md §9).
func UbuntuServices() map[string]string {
	return map[string]string{
		"web":          "apache2.service",
		"mta":          "postfix.service",
		"imap":         "dovecot.service",
		"dns":          "pdns.service",
		"db":           "mariadb.service",
		"ftp":          "pure-ftpd.service",
		"spam":         "rspamd.service",
		"av":           "clamav-daemon.service",
		"ssh":          "ssh.service",
		"cron":         "cron.service",
		"panel-api":    "xcp-api.service",
		"panel-worker": "xcp-worker.service",
	}
}

var phpFPMRe = regexp.MustCompile(`^php-fpm@([5-9]\.[0-9])$`)

// ServiceRegistry resolves logical service IDs to units.
type ServiceRegistry struct {
	units map[string]string
}

// NewServiceRegistry returns a registry using the given ID → unit map.
func NewServiceRegistry(units map[string]string) *ServiceRegistry {
	return &ServiceRegistry{units: units}
}

// Unit returns the systemd unit for a logical ID. "php-fpm@X.Y" maps to the
// Ubuntu/Debian unit "phpX.Y-fpm.service".
func (r *ServiceRegistry) Unit(id string) (string, error) {
	if u, ok := r.units[id]; ok {
		return u, nil
	}
	if m := phpFPMRe.FindStringSubmatch(id); m != nil {
		return "php" + m[1] + "-fpm.service", nil
	}
	return "", invalid("unknown service %q", id)
}

// Action is a service state change.
type Action string

// Service actions.
const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
	ActionReload  Action = "reload"
	// ActionReloadOrRestart reloads a running unit and starts a stopped one.
	ActionReloadOrRestart Action = "reload-or-restart"
	// ActionDaemonReload reloads systemd's unit files; the unit is ignored.
	ActionDaemonReload Action = "daemon-reload"
)

// UnitStatus is the state of a systemd unit.
type UnitStatus struct {
	ActiveState string
	SubState    string
	MainPID     int32
	Enabled     bool
}

// ServiceManager controls systemd units.
type ServiceManager interface {
	Status(ctx context.Context, unit string) (UnitStatus, error)
	Do(ctx context.Context, unit string, a Action) error
}

// SystemctlPath is the binary used by Systemctl; add it to the runner's allow-list.
const SystemctlPath = "/usr/bin/systemctl"

// Systemctl implements ServiceManager with the systemctl binary.
type Systemctl struct {
	Run *execx.Runner
}

// Status implements ServiceManager.
func (s Systemctl) Status(ctx context.Context, unit string) (UnitStatus, error) {
	res, err := s.Run.Run(ctx, execx.Cmd{
		Path: SystemctlPath,
		Args: []string{"show", "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState", "--", unit},
	})
	if err != nil {
		return UnitStatus{}, err
	}
	return parseShow(res.Stdout)
}

// Do implements ServiceManager.
func (s Systemctl) Do(ctx context.Context, unit string, a Action) error {
	switch a {
	case ActionDaemonReload:
		_, err := s.Run.Run(ctx, execx.Cmd{Path: SystemctlPath, Args: []string{"daemon-reload"}})
		return err
	case ActionStart, ActionStop, ActionRestart, ActionReload, ActionReloadOrRestart:
	default:
		return invalid("unknown action %q", a)
	}
	_, err := s.Run.Run(ctx, execx.Cmd{Path: SystemctlPath, Args: []string{string(a), "--", unit}})
	return err
}

// parseShow parses "Key=Value" lines from systemctl show.
func parseShow(out []byte) (UnitStatus, error) {
	props := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			props[k] = v
		}
	}
	if props["LoadState"] == "not-found" {
		return UnitStatus{}, ErrNotInstalled
	}
	if props["ActiveState"] == "" {
		return UnitStatus{}, fmt.Errorf("unexpected systemctl show output: %q", out)
	}
	pid, _ := strconv.ParseInt(props["MainPID"], 10, 32)
	st := UnitStatus{ActiveState: props["ActiveState"], SubState: props["SubState"], MainPID: int32(pid)}
	switch props["UnitFileState"] {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated":
		st.Enabled = true
	}
	return st, nil
}

// Services is the service part of the agent.
type Services struct {
	Registry *ServiceRegistry
	Manager  ServiceManager
}

// Status resolves id and returns its unit and state.
func (s Services) Status(ctx context.Context, id string) (string, UnitStatus, error) {
	unit, err := s.Registry.Unit(id)
	if err != nil {
		return "", UnitStatus{}, err
	}
	st, err := s.Manager.Status(ctx, unit)
	return unit, st, err
}

// Do resolves id and applies the action.
func (s Services) Do(ctx context.Context, id string, a Action) error {
	unit, err := s.Registry.Unit(id)
	if err != nil {
		return err
	}
	return s.Manager.Do(ctx, unit, a)
}
