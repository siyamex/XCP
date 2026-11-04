package agent

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/validate"
)

// WebOptions are the per-domain web settings of a user (ADR-0020):
// custom error pages, hotlink protection, an IP blocker, compression and
// browser caching. The panel stores them as JSON, so the tags matter.
type WebOptions struct {
	ErrorPages    map[string]string `json:"error_pages"` // status code -> URL path of the page, like "/errors/404.html"
	Hotlink       Hotlink           `json:"hotlink"`
	Blocked       []string          `json:"blocked"`  // addresses and networks refused
	Compress      bool              `json:"compress"` // gzip text responses
	CacheRules    []CacheRule       `json:"cache_rules"`
	ProtectedDirs []ProtectedDir    `json:"protected_dirs"` // folders behind a password
}

// Hotlink stops other sites from embedding this site's files.
type Hotlink struct {
	Enabled    bool     `json:"enabled"`
	Hosts      []string `json:"hosts"`       // other sites that may embed (this one always may)
	Extensions []string `json:"extensions"`  // protected file types: jpg, png, mp4, ...
	AllowEmpty bool     `json:"allow_empty"` // requests without a referrer (direct visits, privacy tools) pass
}

// ProtectedDir is a folder of the site that needs a user name and password
// (HTTP basic authentication). Hash is a bcrypt hash; the password itself is
// never stored.
type ProtectedDir struct {
	Path  string   `json:"path"`  // folder below the document root, like "/private"
	Realm string   `json:"realm"` // the prompt's title
	Users []HtUser `json:"users"`
}

// HtUser is one login of a protected folder.
type HtUser struct {
	Name string `json:"name"`
	Hash string `json:"hash,omitempty"`
}

// Bounds of directory privacy.
const (
	MaxProtectedDirs  = 20
	MaxProtectedUsers = 30
)

var (
	htNameRe  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,40}$`)
	htRealmRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,50}$`)
	bcryptRe  = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

// CacheRule tells browsers to keep files of some types for Days.
type CacheRule struct {
	Extensions []string `json:"extensions"`
	Days       int      `json:"days"`
}

// Bounds of the web options.
const (
	MaxErrorPages   = 10
	MaxBlocked      = 200
	MaxHotlinkHosts = 50
	MaxExtensions   = 30
	MaxCacheRules   = 20
)

// ErrorCodes are the statuses that can have a page of their own.
var ErrorCodes = []string{"400", "401", "403", "404", "500", "502", "503"}

var (
	errorPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,200}$`)
	extRe       = regexp.MustCompile(`^[a-z0-9]{1,10}$`)
)

func cleanExts(field string, in []string) ([]string, error) {
	if len(in) > MaxExtensions {
		return nil, fmt.Errorf("%s: at most %d file types", field, MaxExtensions)
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
		if !extRe.MatchString(e) {
			return nil, fmt.Errorf("%s: %q is not a file type like jpg", field, e)
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Clean checks the options and returns them in their normal form
// (lower-case, sorted, without duplicates).
func (o WebOptions) Clean() (WebOptions, error) {
	out := WebOptions{ErrorPages: map[string]string{}, Compress: o.Compress, Blocked: []string{}, CacheRules: []CacheRule{}}
	if len(o.ErrorPages) > MaxErrorPages {
		return out, fmt.Errorf("at most %d error pages", MaxErrorPages)
	}
	for code, p := range o.ErrorPages {
		if !slices.Contains(ErrorCodes, code) {
			return out, fmt.Errorf("error page %q: the codes are %s", code, strings.Join(ErrorCodes, ", "))
		}
		if p == "" {
			continue // unset
		}
		if !errorPathRe.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
			return out, fmt.Errorf("error page %s: %q is not a clean URL path like /errors/%s.html", code, p, code)
		}
		out.ErrorPages[code] = p
	}
	if len(o.Blocked) > MaxBlocked {
		return out, fmt.Errorf("at most %d blocked addresses", MaxBlocked)
	}
	for _, b := range o.Blocked {
		p, err := addrOrPrefix(strings.TrimSpace(b))
		if err != nil {
			return out, fmt.Errorf("blocked %q: not an IP address or network", b)
		}
		if p.Bits() == 0 {
			return out, fmt.Errorf("blocked %q would block everyone", b)
		}
		s := p.String()
		if p.IsSingleIP() {
			s = p.Addr().String()
		}
		if !slices.Contains(out.Blocked, s) {
			out.Blocked = append(out.Blocked, s)
		}
	}
	h := o.Hotlink
	out.Hotlink = Hotlink{Enabled: h.Enabled, AllowEmpty: h.AllowEmpty, Hosts: []string{}, Extensions: []string{}}
	if len(h.Hosts) > MaxHotlinkHosts {
		return out, fmt.Errorf("at most %d allowed sites", MaxHotlinkHosts)
	}
	for _, host := range h.Hosts {
		n, err := validate.Domain(strings.TrimSpace(host))
		if err != nil {
			return out, fmt.Errorf("hotlink site %q is not a domain name", host)
		}
		if !slices.Contains(out.Hotlink.Hosts, n) {
			out.Hotlink.Hosts = append(out.Hotlink.Hosts, n)
		}
	}
	var err error
	if out.Hotlink.Extensions, err = cleanExts("hotlink", h.Extensions); err != nil {
		return out, err
	}
	if h.Enabled && len(out.Hotlink.Extensions) == 0 {
		return out, fmt.Errorf("hotlink protection needs at least one file type")
	}
	if len(o.CacheRules) > MaxCacheRules {
		return out, fmt.Errorf("at most %d caching rules", MaxCacheRules)
	}
	seen := map[string]bool{}
	for _, r := range o.CacheRules {
		if r.Days < 1 || r.Days > 365 {
			return out, fmt.Errorf("caching: days are 1 to 365")
		}
		exts, err := cleanExts("caching", r.Extensions)
		if err != nil {
			return out, err
		}
		if len(exts) == 0 {
			return out, fmt.Errorf("caching: a rule needs at least one file type")
		}
		for _, e := range exts {
			if seen[e] {
				return out, fmt.Errorf("caching: %s has two rules", e)
			}
			seen[e] = true
		}
		out.CacheRules = append(out.CacheRules, CacheRule{Extensions: exts, Days: r.Days})
	}
	if len(o.ProtectedDirs) > MaxProtectedDirs {
		return out, fmt.Errorf("at most %d protected folders", MaxProtectedDirs)
	}
	seenDir := map[string]bool{}
	out.ProtectedDirs = []ProtectedDir{}
	for _, d := range o.ProtectedDirs {
		if !errorPathRe.MatchString(d.Path) || strings.Contains(d.Path, "..") || strings.Contains(d.Path, "//") || d.Path == "/" {
			return out, fmt.Errorf("protected folder %q is not a clean folder like /private", d.Path)
		}
		d.Path = strings.TrimSuffix(d.Path, "/")
		if seenDir[d.Path] {
			return out, fmt.Errorf("protected folder %s is listed twice", d.Path)
		}
		seenDir[d.Path] = true
		if d.Realm == "" {
			d.Realm = "Restricted area"
		}
		if !htRealmRe.MatchString(d.Realm) {
			return out, fmt.Errorf("protected folder %s: the title is 1 to 50 letters, digits, spaces, . _ -", d.Path)
		}
		if len(d.Users) > MaxProtectedUsers {
			return out, fmt.Errorf("protected folder %s: at most %d users", d.Path, MaxProtectedUsers)
		}
		seenUser := map[string]bool{}
		users := []HtUser{}
		for _, u := range d.Users {
			if !htNameRe.MatchString(u.Name) {
				return out, fmt.Errorf("protected folder %s: user name %q is 1 to 40 letters, digits and . _ @ -", d.Path, u.Name)
			}
			if !bcryptRe.MatchString(u.Hash) {
				return out, fmt.Errorf("protected folder %s: user %s has no valid password hash", d.Path, u.Name)
			}
			if seenUser[u.Name] {
				return out, fmt.Errorf("protected folder %s: user %s is listed twice", d.Path, u.Name)
			}
			seenUser[u.Name] = true
			users = append(users, u)
		}
		slices.SortFunc(users, func(a, b HtUser) int { return strings.Compare(a.Name, b.Name) })
		out.ProtectedDirs = append(out.ProtectedDirs, ProtectedDir{Path: d.Path, Realm: d.Realm, Users: users})
	}
	slices.SortFunc(out.ProtectedDirs, func(a, b ProtectedDir) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(out.Blocked)
	slices.Sort(out.Hotlink.Hosts)
	slices.Sort(out.Hotlink.Extensions)
	return out, nil
}

// directives renders the options that are not an access rule, for the body
// of a virtual host. Clean must have accepted them. host is the vhost's name.
func (o WebOptions) directives(host string) string {
	var b strings.Builder
	for _, code := range ErrorCodes {
		if p := o.ErrorPages[code]; p != "" {
			fmt.Fprintf(&b, "    ErrorDocument %s \"%s\"\n", code, p)
		}
	}
	if o.Hotlink.Enabled && len(o.Hotlink.Extensions) > 0 {
		names := []string{regexp.QuoteMeta(strings.TrimPrefix(host, "*."))}
		for _, h := range o.Hotlink.Hosts {
			names = append(names, regexp.QuoteMeta(h))
		}
		b.WriteString("    RewriteEngine On\n")
		if o.Hotlink.AllowEmpty {
			b.WriteString("    RewriteCond %{HTTP_REFERER} !^$\n")
		}
		fmt.Fprintf(&b, "    RewriteCond %%{HTTP_REFERER} !^https?://([^/]+\\.)?(%s)(:[0-9]+)?(/|$) [NC]\n", strings.Join(names, "|"))
		fmt.Fprintf(&b, "    RewriteRule \"\\.(%s)$\" - [F,NC]\n", strings.Join(o.Hotlink.Extensions, "|"))
	}
	if o.Compress {
		b.WriteString("    <IfModule mod_deflate.c>\n        AddOutputFilterByType DEFLATE text/html text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml\n    </IfModule>\n")
	}
	for _, r := range o.CacheRules {
		fmt.Fprintf(&b, "    <IfModule mod_expires.c>\n        <FilesMatch \"\\.(%s)$\">\n            ExpiresActive On\n            ExpiresDefault \"access plus %d days\"\n        </FilesMatch>\n    </IfModule>\n", strings.Join(r.Extensions, "|"), r.Days)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// addrOrPrefix parses an address (a network of one) or a network.
func addrOrPrefix(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}
