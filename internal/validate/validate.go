// Package validate holds every input validator (07-security.md §7).
// The API, CLI, agent and importers all use these same functions, so a value
// accepted in one place is accepted everywhere.
//
// Validators that normalise input return the normalised value; always use it
// instead of the original.
package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/siyamex/XCP/internal/fsx"
)

// ErrValidation matches every *Error with errors.Is.
var ErrValidation = errors.New("validation failed")

// Error codes, stable for API clients (problem+json "code").
const (
	CodeRequired     = "required"
	CodeTooLong      = "too_long"
	CodeTooShort     = "too_short"
	CodeFormat       = "invalid_format"
	CodeReserved     = "reserved"
	CodePublicSuffix = "public_suffix"
	CodeOutOfRange   = "out_of_range"
)

// Error describes why a value was rejected.
type Error struct {
	Field   string // set by the caller with WithField; empty inside validators
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Field != "" {
		return e.Field + ": " + e.Message
	}
	return e.Message
}

// Is makes errors.Is(err, ErrValidation) true.
func (e *Error) Is(target error) bool { return target == ErrValidation }

// WithField returns err with Field set if err is an *Error; other errors are returned unchanged.
func WithField(err error, field string) error {
	var ve *Error
	if errors.As(err, &ve) {
		c := *ve
		c.Field = field
		return &c
	}
	return err
}

func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// reservedUsernames are system, service and panel accounts. "test" is reserved
// because MySQL has historically granted anonymous access to test_% databases.
var reservedUsernames = map[string]bool{
	"root": true, "bin": true, "daemon": true, "adm": true, "lp": true, "sync": true,
	"shutdown": true, "halt": true, "mail": true, "news": true, "uucp": true,
	"operator": true, "games": true, "ftp": true, "nobody": true, "sshd": true,
	"sudo": true, "wheel": true, "staff": true, "users": true, "admin": true,
	"www": true, "wwwdata": true, "apache": true, "nginx": true, "httpd": true, "lsadm": true,
	"mysql": true, "mariadb": true, "postgres": true, "redis": true, "memcache": true,
	"postfix": true, "dovecot": true, "dovenull": true, "vmail": true, "exim": true,
	"clamav": true, "clamupdate": true, "rspamd": true, "pdns": true, "named": true, "bind": true,
	"systemd": true, "messagebus": true, "polkitd": true, "syslog": true, "chrony": true,
	"ubuntu": true, "debian": true, "centos": true, "almalinux": true, "rocky": true,
	"xcp": true, "test": true, "all": true, "default": true, "virtfs": true,
}

// Username checks a hosting account (Linux) username.
func Username(s string) error {
	switch {
	case s == "":
		return fail(CodeRequired, "username is required")
	case len(s) > 16:
		return fail(CodeTooLong, "username must be at most 16 characters")
	case !usernameRe.MatchString(s):
		return fail(CodeFormat, "username must start with a-z and contain only a-z and 0-9")
	case reservedUsernames[s]:
		return fail(CodeReserved, "username %q is reserved", s)
	}
	return nil
}

// Password limits. The upper bound stops oversized inputs to argon2id.
const (
	MinPasswordLen = 10
	MaxPasswordLen = 1024
)

// Password checks length and forbidden characters. Strength rules
// (ADM-SEC-07) are applied separately by the auth package.
func Password(s string) error {
	switch {
	case len(s) < MinPasswordLen:
		return fail(CodeTooShort, "password must be at least %d characters", MinPasswordLen)
	case len(s) > MaxPasswordLen:
		return fail(CodeTooLong, "password must be at most %d bytes", MaxPasswordLen)
	case strings.ContainsAny(s, "\x00\r\n"):
		return fail(CodeFormat, "password must not contain NUL or line breaks")
	}
	return nil
}

// Port checks a TCP/UDP port number.
func Port(p int) error {
	if p < 1 || p > 65535 {
		return fail(CodeOutOfRange, "port must be between 1 and 65535")
	}
	return nil
}

// IP parses an IPv4 or IPv6 address (no zone). IPv4-mapped IPv6 is unmapped.
func IP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fail(CodeFormat, "%q is not a valid IP address", s)
	}
	return a.Unmap(), nil
}

// CIDR parses an address or prefix ("203.0.113.0/24", "2001:db8::/32",
// or a bare address meaning /32 or /128) and returns it masked.
func CIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := IP(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, fail(CodeFormat, "%q is not a valid CIDR range", s)
	}
	return p.Masked(), nil
}

// RelPath validates a path relative to an account's home and returns it cleaned.
func RelPath(s string) (string, error) {
	c, err := fsx.CleanRel(s)
	if err != nil {
		return "", fail(CodeFormat, "invalid path: %v", err)
	}
	return c, nil
}
