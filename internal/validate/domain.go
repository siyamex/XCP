package validate

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// MaxDomainLen is the DNS limit for a name in presentation form, without the trailing dot.
const MaxDomainLen = 253

// IDNA2008 non-transitional (ß stays ß), hostname rules (letters, digits, hyphen).
// Length limits are checked by Domain itself so they get the right error code.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(true),
	idna.Transitional(false),
)

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Domain validates a domain name and returns it in lower-case ASCII (punycode)
// form. Unicode names (IDN) are converted. A public suffix on its own
// ("com", "co.uk") is rejected.
func Domain(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return "", fail(CodeRequired, "domain is required")
	}
	if len(s) > 4*MaxDomainLen { // cheap guard before IDNA processing
		return "", fail(CodeTooLong, "domain is too long")
	}
	if !utf8.ValidString(s) {
		// IDNA would turn invalid bytes into U+FFFD and punycode it.
		return "", fail(CodeFormat, "domain is not valid UTF-8")
	}
	ascii, err := idnaProfile.ToASCII(s)
	if err != nil {
		return "", fail(CodeFormat, "%q is not a valid domain name", s)
	}
	if len(ascii) > MaxDomainLen {
		return "", fail(CodeTooLong, "domain must be at most %d characters", MaxDomainLen)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fail(CodeFormat, "%q must have at least two labels (like example.com)", s)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fail(CodeFormat, "%q is not a valid domain name", s)
		}
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return "", fail(CodeFormat, "%q looks like an IP address, not a domain", s)
	}
	if ps, _ := publicsuffix.PublicSuffix(ascii); ps == ascii {
		return "", fail(CodePublicSuffix, "%q is a public suffix and cannot be hosted", s)
	}
	return ascii, nil
}

// WildcardDomain accepts "*.example.com" or a plain domain. The returned
// value keeps the "*." prefix when present.
func WildcardDomain(s string) (string, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		d, err := Domain(rest)
		if err != nil {
			return "", err
		}
		return "*." + d, nil
	}
	return Domain(s)
}

// DomainUnicode returns the human-readable form of an ASCII domain, for display only.
func DomainUnicode(ascii string) string {
	u, err := idna.Display.ToUnicode(ascii)
	if err != nil {
		return ascii
	}
	return u
}

// IsSubdomainOf reports whether child equals parent or is below it.
// Both must already be normalised by Domain.
func IsSubdomainOf(child, parent string) bool {
	return child == parent || strings.HasSuffix(child, "."+parent)
}

var (
	// Mailbox names: no '+', which is the plus-addressing delimiter.
	mailboxRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	// Other local parts (forward targets, contacts): a safe subset of RFC 5322
	// without spaces, quotes, '|' or other characters special in mail maps.
	localPartRe = regexp.MustCompile(`^[a-z0-9_%+=-]([a-z0-9._%+=-]{0,62}[a-z0-9_%+=-])?$`)
)

// MailboxName validates the local part of a mailbox hosted on this server and
// returns it lower-cased.
func MailboxName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "":
		return "", fail(CodeRequired, "mailbox name is required")
	case len(s) > 64:
		return "", fail(CodeTooLong, "mailbox name must be at most 64 characters")
	case !mailboxRe.MatchString(s) || strings.Contains(s, ".."):
		return "", fail(CodeFormat, "mailbox name may contain a-z, 0-9, '.', '_' and '-', and must start and end with a letter or digit")
	}
	return s, nil
}

// Email validates an address such as a forward destination or contact
// address and returns it normalised (lower case, punycode domain).
func Email(s string) (string, error) {
	s = strings.TrimSpace(s)
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return "", fail(CodeFormat, "%q is not a valid email address", s)
	}
	local := strings.ToLower(s[:at])
	if len(local) > 64 || !localPartRe.MatchString(local) || strings.Contains(local, "..") {
		return "", fail(CodeFormat, "%q is not a valid email address", s)
	}
	domain, err := Domain(s[at+1:])
	if err != nil {
		return "", fail(CodeFormat, "%q is not a valid email address", s)
	}
	return local + "@" + domain, nil
}
