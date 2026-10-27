package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "xcp.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestLoadOverridesAndResolvesRelativePaths(t *testing.T) {
	p := writeConfig(t, `
[api]
listen = "127.0.0.1:2443"
insecure_dev_http = true
session_idle = "10m"

[agent]
fake = true

[db]
path = "data/xcp.db"

[log]
format = "text"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Listen != "127.0.0.1:2443" || !cfg.API.InsecureDevHTTP || !cfg.Agent.Fake {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.API.SessionIdle.Duration != 10*time.Minute {
		t.Errorf("session_idle = %v", cfg.API.SessionIdle)
	}
	if cfg.API.SessionMax.Duration != 12*time.Hour {
		t.Errorf("session_max default lost: %v", cfg.API.SessionMax)
	}
	want := filepath.Join(filepath.Dir(p), "data", "xcp.db")
	if cfg.DB.Path != want {
		t.Errorf("db.path = %q, want %q", cfg.DB.Path, want)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := map[string]struct {
		body    string
		wantErr string
	}{
		"unknown key":        {`[api]` + "\n" + `lisen = ":1"`, "unknown keys"},
		"bad listen":         {`[api]` + "\n" + `listen = "nope"`, "api.listen"},
		"bad level":          {`[log]` + "\n" + `level = "loud"`, "log.level"},
		"no tls without dev": {`[api]` + "\n" + `tls_cert = ""`, "tls_cert"},
		"idle > max":         {`[api]` + "\n" + `session_idle = "24h"`, "session_idle"},
		"bad duration":       {`[api]` + "\n" + `session_idle = "soon"`, "parse config"},
		"relative managed":   {`[agent]` + "\n" + `managed_dirs = ["etc/x"]`, "agent.managed_dirs"},
		"root managed":       {`[agent]` + "\n" + `managed_dirs = ["/"]`, "agent.managed_dirs"},
		"unclean managed":    {`[agent]` + "\n" + `managed_dirs = ["/etc/../x"]`, "agent.managed_dirs"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
