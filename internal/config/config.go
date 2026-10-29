// Package config loads /etc/xcp/xcp.toml.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is where production installs keep the config file.
const DefaultPath = "/etc/xcp/xcp.toml"

// Config is the full configuration shared by all XCP binaries.
// Each binary reads only the sections it needs.
type Config struct {
	API   API   `toml:"api"`
	Agent Agent `toml:"agent"`
	DB    DB    `toml:"db"`
	Log   Log   `toml:"log"`
	Paths Paths `toml:"paths"`
}

// API configures xcp-api.
type API struct {
	Listen string `toml:"listen"`
	// TLSCert and TLSKey are required unless InsecureDevHTTP is true.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// InsecureDevHTTP serves plain HTTP. Only for local development.
	InsecureDevHTTP bool     `toml:"insecure_dev_http"`
	SessionIdle     Duration `toml:"session_idle"`
	SessionMax      Duration `toml:"session_max"`
}

// Agent configures how xcp-api/xcp-worker reach xcp-agent, and xcp-agent itself.
type Agent struct {
	Socket string `toml:"socket"`
	// Fake uses an in-memory agent that records operations. Dev/test only.
	Fake bool `toml:"fake"`
	// APIUser is the Linux user xcp-api and xcp-worker run as; only it and
	// root may call the agent.
	APIUser string `toml:"api_user"`
	// ManagedDirs are where FileWriteManaged may write. Empty means the
	// built-in defaults (agent.DefaultManagedDirs).
	ManagedDirs []string `toml:"managed_dirs"`
}

// DB configures the panel database.
type DB struct {
	Path string `toml:"path"`
}

// Log configures structured logging.
type Log struct {
	Level  string `toml:"level"`  // debug, info, warn, error
	Format string `toml:"format"` // json, text
}

// Paths holds well-known directories.
type Paths struct {
	StateDir  string `toml:"state_dir"`
	RunDir    string `toml:"run_dir"`
	HomesRoot string `toml:"homes_root"`
	// SecretsDir holds master.key (root/xcp only, 0700).
	SecretsDir string `toml:"secrets_dir"`
}

// MasterKeyFile is the secretbox key used to encrypt secrets in the database.
func (p Paths) MasterKeyFile() string { return filepath.Join(p.SecretsDir, "master.key") }

// PDNSKeyFile holds the PowerDNS API key; only root (xcp-agent) reads it.
func (p Paths) PDNSKeyFile() string { return filepath.Join(p.SecretsDir, "pdns-api-key") }

// Duration wraps time.Duration so TOML can use strings like "30m".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Default returns production defaults.
func Default() Config {
	return Config{
		API: API{
			Listen:      ":2443",
			TLSCert:     "/etc/xcp/ssl/panel.crt",
			TLSKey:      "/etc/xcp/ssl/panel.key",
			SessionIdle: Duration{30 * time.Minute},
			SessionMax:  Duration{12 * time.Hour},
		},
		Agent: Agent{Socket: "/run/xcp/agent.sock", APIUser: "xcp"},
		DB:    DB{Path: "/var/lib/xcp/xcp.db"},
		Log:   Log{Level: "info", Format: "json"},
		Paths: Paths{ //nolint:gosec // G101: SecretsDir is a directory path, not a credential
			StateDir:   "/var/lib/xcp",
			RunDir:     "/run/xcp",
			HomesRoot:  "/home",
			SecretsDir: "/etc/xcp/secrets",
		},
	}
}

// Load reads the file at path on top of the defaults and validates the result.
// Relative paths inside the file are resolved against the file's directory,
// so dev configs can live in the repo.
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path) //nolint:gosec // path comes from the operator (flag), not from users
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return cfg, fmt.Errorf("config %s: unknown keys: %v", path, undec)
	}
	cfg.resolveRelative(filepath.Dir(path))
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) resolveRelative(base string) {
	for _, p := range []*string{
		&c.API.TLSCert, &c.API.TLSKey, &c.Agent.Socket, &c.DB.Path,
		&c.Paths.StateDir, &c.Paths.RunDir, &c.Paths.HomesRoot, &c.Paths.SecretsDir,
	} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
}

// Validate checks values that would otherwise fail late or insecurely.
func (c Config) Validate() error {
	var errs []error
	if _, _, err := net.SplitHostPort(c.API.Listen); err != nil {
		errs = append(errs, fmt.Errorf("api.listen %q: %w", c.API.Listen, err))
	}
	if !c.API.InsecureDevHTTP && (c.API.TLSCert == "" || c.API.TLSKey == "") {
		errs = append(errs, errors.New("api.tls_cert and api.tls_key are required (or set api.insecure_dev_http for local dev)"))
	}
	if c.API.SessionIdle.Duration <= 0 || c.API.SessionMax.Duration < c.API.SessionIdle.Duration {
		errs = append(errs, errors.New("api.session_idle must be > 0 and <= api.session_max"))
	}
	if !c.Agent.Fake && c.Agent.Socket == "" {
		errs = append(errs, errors.New("agent.socket is required unless agent.fake is true"))
	}
	for _, d := range c.Agent.ManagedDirs {
		if !strings.HasPrefix(d, "/") || path.Clean(d) != d || d == "/" {
			errs = append(errs, fmt.Errorf("agent.managed_dirs: %q must be a clean absolute path below /", d))
		}
	}
	if c.DB.Path == "" {
		errs = append(errs, errors.New("db.path is required"))
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level) {
		errs = append(errs, fmt.Errorf("log.level %q: want debug, info, warn or error", c.Log.Level))
	}
	if !slices.Contains([]string{"json", "text"}, c.Log.Format) {
		errs = append(errs, fmt.Errorf("log.format %q: want json or text", c.Log.Format))
	}
	return errors.Join(errs...)
}
