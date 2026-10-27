// Package logging builds the slog logger used by every binary.
// It redacts secrets so they never reach log files (07-security.md §8).
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// Redacted replaces secret values in log output.
const Redacted = "[REDACTED]"

// TokenPrefix marks XCP API tokens; any string value starting with it
// is redacted, whatever the attribute key is.
const TokenPrefix = "xcp_"

// secretKeyParts: an attribute whose key contains any of these is redacted.
var secretKeyParts = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "privkey", "credential", "cookie", "authorization"}

// New returns a JSON or text logger writing to w at the given level.
// Unknown levels fall back to info; config validation rejects them earlier.
func New(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       parseLevel(level),
		ReplaceAttr: redact,
	}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	if IsSecretKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() == slog.KindString && strings.HasPrefix(a.Value.String(), TokenPrefix) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// IsSecretKey reports whether an attribute or field name looks like it holds a secret.
func IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, part := range secretKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}
