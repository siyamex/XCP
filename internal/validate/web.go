package validate

import (
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// MaxDocRootDepth bounds the folders in a document root.
const MaxDocRootDepth = 8

var docRootElemRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

// reservedDocRoots are home folders that hold private data; serving them
// would publish PHP sessions, mail or keys.
var reservedDocRoots = []string{"tmp", "mail", "etc", "logs", "ssl", "backups"}

// DocRoot validates a website's document root, relative to the account's
// home folder, and returns it cleaned ("/public_html/shop/" becomes
// "public_html/shop"). Only plain names are allowed: no hidden folders, no
// "..", never the home folder itself or a folder that holds private data.
func DocRoot(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "", fail(CodeRequired, "document root is required (the home folder itself cannot be one)")
	}
	if len(s) > 255 {
		return "", fail(CodeTooLong, "document root must be at most 255 characters")
	}
	elems := strings.Split(s, "/")
	if len(elems) > MaxDocRootDepth {
		return "", fail(CodeFormat, "document root may be at most %d folders deep", MaxDocRootDepth)
	}
	for _, e := range elems {
		if !docRootElemRe.MatchString(e) {
			return "", fail(CodeFormat, "%q: folder names may use letters, digits, '.', '_' and '-' and must not start with '.' or '-'", e)
		}
	}
	if slices.Contains(reservedDocRoots, strings.ToLower(elems[0])) {
		return "", fail(CodeReserved, "%q holds private data and cannot be a document root", elems[0])
	}
	return path.Clean(s), nil
}

var redirectPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// RedirectPath validates the path a redirect applies to: "/" (the whole
// site) or "/a/b" made of URL-safe characters. A trailing slash is removed.
func RedirectPath(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		return "/", nil
	}
	s = strings.TrimRight(s, "/")
	if len(s) > 255 {
		return "", fail(CodeTooLong, "path must be at most 255 characters")
	}
	if !redirectPathRe.MatchString(s) {
		return "", fail(CodeFormat, "path must start with / and use letters, digits, '.', '_', '~' and '-'")
	}
	for _, e := range strings.Split(s[1:], "/") {
		if e == "." || e == ".." {
			return "", fail(CodeFormat, "path must not contain . or .. segments")
		}
	}
	return s, nil
}

// redirectTargetRe allows the URL characters of RFC 3986 except those with a
// meaning in Apache's config or its regex replacements: quotes, backslash,
// '$', spaces and control characters.
var redirectTargetRe = regexp.MustCompile(`^[A-Za-z0-9._~:/?#\[\]@!&()*+,;=%-]+$`)

// RedirectTarget validates a redirect destination: an absolute http or https
// URL without credentials. It ends up in the web server's config.
func RedirectTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fail(CodeRequired, "destination URL is required")
	}
	if len(s) > 2000 {
		return "", fail(CodeTooLong, "destination URL must be at most 2000 characters")
	}
	bad := func() (string, error) {
		return "", fail(CodeFormat, "destination must be a full http:// or https:// URL without spaces, quotes or '$'")
	}
	if !redirectTargetRe.MatchString(s) {
		return bad()
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" {
		return bad()
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err != nil {
		if _, err := Domain(host); err != nil {
			return bad()
		}
	}
	return s, nil
}

// RedirectCode accepts the HTTP redirect status codes a redirect may use.
func RedirectCode(code int) error {
	switch code {
	case 301, 302, 307, 308:
		return nil
	}
	return fail(CodeOutOfRange, "redirect type must be 301, 302, 307 or 308")
}

var subLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// SubdomainLabel validates what goes before the parent domain of a
// subdomain: "blog", "a.b", or "*" for a wildcard. It returns it in lower case.
func SubdomainLabel(s string) (string, error) {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
	if s == "" {
		return "", fail(CodeRequired, "subdomain is required")
	}
	if s == "*" || subLabelRe.MatchString(s) {
		return s, nil
	}
	return "", fail(CodeFormat, "%q is not a valid subdomain (letters, digits and '-', or * for all)", s)
}

// Registrable returns the registered domain (eTLD+1) a domain belongs to:
// "shop.example.co.uk" and "*.example.co.uk" give "example.co.uk".
func Registrable(name string) string {
	name = strings.TrimPrefix(name, "*.")
	if r, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return r
	}
	return name
}
