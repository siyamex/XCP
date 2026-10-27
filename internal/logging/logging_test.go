package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "debug", "json")
	log.Info("login",
		"user", "alice",
		"password", "hunter2",
		"DB_Password", "s3cret",
		"header", "xcp_abc_0123456789",
		"note", "not a secret",
	)
	log.WithGroup("req").Info("nested", "api_token", "tok-123")

	out := buf.String()
	for _, leak := range []string{"hunter2", "s3cret", "xcp_abc_0123456789", "tok-123"} {
		if strings.Contains(out, leak) {
			t.Errorf("secret %q leaked into log: %s", leak, out)
		}
	}
	for _, keep := range []string{"alice", "not a secret"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret %q missing from log: %s", keep, out)
		}
	}
}

func TestLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "warn", "text")
	log.Info("hidden")
	log.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level filter wrong: %q", buf.String())
	}
}
