// Package fwcfg is the firewall's configuration (ADR-0017): its shape and
// rules, shared by the panel's firewall service and xcp-logd, which reads
// the brute-force settings and bans addresses.
package fwcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Key is the setting that holds the configuration.
const Key = "firewall"

// JobApply gives the agent the firewall's rules. One at a time; a request
// while one is queued is folded into it.
const JobApply = "firewall.apply"

// Port is a port or a range (30000-30999) of a protocol.
type Port struct {
	Port    string `json:"port"`
	Proto   string `json:"proto"` // tcp or udp
	Comment string `json:"comment"`
}

// Entry is an address or network.
type Entry struct {
	CIDR    string `json:"cidr"`
	Comment string `json:"comment"`
}

// RateLimit limits new connections per source address to some TCP ports.
type RateLimit struct {
	Enabled   bool     `json:"enabled"`
	PerMinute int      `json:"per_minute"`
	Ports     []string `json:"ports"`
}

// Brute is the brute-force protection (ADM-SEC-01).
type Brute struct {
	Enabled        bool     `json:"enabled"`
	Threshold      int      `json:"threshold"`       // failed logins...
	WindowMinutes  int      `json:"window_minutes"`  // ...within this long
	BanMinutes     int      `json:"ban_minutes"`     // for this long
	PermanentAfter int      `json:"permanent_after"` // ban for good from this many bans of an address; 0 never
	Sources        []string `json:"sources"`         // ssh, mail, ftp, panel
}

// Config is the firewall.
type Config struct {
	Enabled  bool                `json:"enabled"`
	Policy   string              `json:"policy"` // open: everything not refused is let in; closed: only the open ports
	SSHPort  int                 `json:"ssh_port"`
	Ports    []Port              `json:"ports"`
	Allow    []Entry             `json:"allow"` // always let in, whatever else says
	Deny     []Entry             `json:"deny"`
	Restrict map[string][]string `json:"restrict"` // panel, ssh, ftp: only these networks may reach the service
	Rate     RateLimit           `json:"rate_limit"`
	Brute    Brute               `json:"brute"`
}

// Services whose access can be restricted to some networks (ADM-SEC-03).
var Services = []string{"panel", "ssh", "ftp"}

// Sources of failed logins.
var Sources = []string{store.BanSSH, store.BanMail, store.BanFTP, store.BanPanel}

// Limits.
const (
	MaxPorts    = 200
	MaxEntries  = 2000
	MaxRestrict = 200
)

// Default returns the firewall of a new server: off, and with the ports of
// the services XCP installs ready for when the admin turns on "closed".
func Default(panelPort int) Config {
	tcp := func(p, c string) Port { return Port{Port: p, Proto: "tcp", Comment: c} }
	ports := []Port{
		tcp("22", "SSH"), tcp("21", "FTP"), tcp("30000-30999", "FTP passive"), tcp("25", "Mail: SMTP"), tcp("465", "Mail: SMTPS"), tcp("587", "Mail: submission"),
		tcp("110", "Mail: POP3"), tcp("995", "Mail: POP3S"), tcp("143", "Mail: IMAP"), tcp("993", "Mail: IMAPS"),
		tcp("53", "DNS"),
		{Port: "53", Proto: "udp", Comment: "DNS"},
		tcp("80", "Web"), tcp("443", "Web (HTTPS)"),
	}
	if panelPort > 0 {
		ports = append(ports, tcp(strconv.Itoa(panelPort), "XCP panel"))
	}
	return Config{
		Policy: "open", SSHPort: 22, Ports: ports, Allow: []Entry{}, Deny: []Entry{}, Restrict: map[string][]string{},
		Rate:  RateLimit{PerMinute: 120, Ports: []string{"22", "21", "465", "587", "110", "995", "143", "993"}},
		Brute: Brute{Enabled: true, Threshold: 10, WindowMinutes: 10, BanMinutes: 60, PermanentAfter: 5, Sources: slices.Clone(Sources)},
	}
}

// Load returns the configuration (the default until saved).
func Load(ctx context.Context, db *store.DB, panelPort int) (Config, error) {
	c := Default(panelPort)
	if err := db.GetSetting(ctx, Key, &c); err != nil && !errors.Is(err, store.ErrNotFound) {
		return c, err
	}
	c.fill(panelPort)
	return c, nil
}

// fill makes nil lists empty (they go to JSON) and gives a saved
// configuration from before a setting existed its default.
func (c *Config) fill(panelPort int) {
	d := Default(panelPort)
	if c.Policy == "" {
		c.Policy = d.Policy
	}
	if c.SSHPort == 0 {
		c.SSHPort = d.SSHPort
	}
	if c.Ports == nil {
		c.Ports = []Port{}
	}
	if c.Allow == nil {
		c.Allow = []Entry{}
	}
	if c.Deny == nil {
		c.Deny = []Entry{}
	}
	if c.Restrict == nil {
		c.Restrict = map[string][]string{}
	}
	if c.Rate.Ports == nil {
		c.Rate.Ports = []string{}
	}
	if c.Brute.Sources == nil {
		c.Brute.Sources = []string{}
	}
}

func bad(field, msg string) error {
	return &validate.Error{Field: field, Code: validate.CodeFormat, Message: msg}
}

var portRe = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)

// checkPort validates "22" or "30000-30999".
func checkPort(field, p string) error {
	if !portRe.MatchString(p) {
		return bad(field, fmt.Sprintf("%q is not a port like 22 or a range like 30000-30999", p))
	}
	lo, hi, _ := strings.Cut(p, "-")
	a, _ := strconv.Atoi(lo)
	b := a
	if hi != "" {
		b, _ = strconv.Atoi(hi)
	}
	if a < 1 || b > 65535 || a > b {
		return bad(field, fmt.Sprintf("%q is out of range (1 to 65535, low to high)", p))
	}
	return nil
}

// PortOpen reports whether a port is within the open ports of a protocol.
func (c Config) PortOpen(port int, proto string) bool {
	for _, p := range c.Ports {
		if p.Proto != proto {
			continue
		}
		lo, hi, _ := strings.Cut(p.Port, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if hi != "" {
			b, _ = strconv.Atoi(hi)
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// ParseCIDR reads an address or network and returns it as a masked prefix:
// a bare address is a /32 or /128.
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Contains reports whether any network of list holds the address.
func Contains(list []string, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, s := range list {
		if p, err := ParseCIDR(s); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// Cidrs returns the networks of entries.
func Cidrs(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.CIDR
	}
	return out
}

func normEntries(field string, es []Entry) ([]Entry, error) {
	if len(es) > MaxEntries {
		return nil, bad(field, fmt.Sprintf("at most %d entries", MaxEntries))
	}
	out := make([]Entry, 0, len(es))
	seen := map[string]bool{}
	for _, e := range es {
		p, err := ParseCIDR(e.CIDR)
		if err != nil {
			return nil, bad(field, fmt.Sprintf("%q is not an IP address or network like 203.0.113.0/24", e.CIDR))
		}
		if len(e.Comment) > 100 || strings.ContainsAny(e.Comment, "\r\n") {
			return nil, bad(field, "a comment is one line of at most 100 characters")
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, Entry{CIDR: p.String(), Comment: strings.TrimSpace(e.Comment)})
		}
	}
	return out, nil
}

// Normalize validates the configuration and puts it in canonical form.
// A closed firewall must keep the panel and SSH reachable.
func (c *Config) Normalize(panelPort int) error {
	c.fill(panelPort)
	if c.Policy != "open" && c.Policy != "closed" {
		return bad("policy", "open or closed")
	}
	if c.SSHPort < 1 || c.SSHPort > 65535 {
		return bad("ssh_port", "1 to 65535")
	}
	if len(c.Ports) > MaxPorts {
		return bad("ports", fmt.Sprintf("at most %d ports", MaxPorts))
	}
	for i, p := range c.Ports {
		if p.Proto != "tcp" && p.Proto != "udp" {
			return bad("ports", "the protocol is tcp or udp")
		}
		if err := checkPort("ports", p.Port); err != nil {
			return err
		}
		if len(p.Comment) > 100 || strings.ContainsAny(p.Comment, "\r\n") {
			return bad("ports", "a comment is one line of at most 100 characters")
		}
		c.Ports[i].Comment = strings.TrimSpace(p.Comment)
	}
	var err error
	if c.Allow, err = normEntries("allow", c.Allow); err != nil {
		return err
	}
	if c.Deny, err = normEntries("deny", c.Deny); err != nil {
		return err
	}
	restrict := map[string][]string{}
	for name, list := range c.Restrict {
		if !slices.Contains(Services, name) {
			return bad("restrict", fmt.Sprintf("%q is not a service you can restrict: panel, ssh or ftp", name))
		}
		if len(list) > MaxRestrict {
			return bad("restrict", fmt.Sprintf("at most %d networks per service", MaxRestrict))
		}
		for _, s := range list {
			p, err := ParseCIDR(s)
			if err != nil {
				return bad("restrict", fmt.Sprintf("%q is not an IP address or network", s))
			}
			restrict[name] = append(restrict[name], p.String())
		}
	}
	c.Restrict = restrict
	if c.Rate.Enabled && (c.Rate.PerMinute < 5 || c.Rate.PerMinute > 100000) {
		return bad("rate_limit", "5 to 100000 new connections per minute")
	}
	if len(c.Rate.Ports) > MaxPorts {
		return bad("rate_limit", "too many ports")
	}
	for _, p := range c.Rate.Ports {
		if err := checkPort("rate_limit", p); err != nil {
			return err
		}
	}
	b := &c.Brute
	switch {
	case b.Threshold < 3 || b.Threshold > 1000:
		return bad("brute", "the threshold is 3 to 1000 failed logins")
	case b.WindowMinutes < 1 || b.WindowMinutes > 1440:
		return bad("brute", "the window is 1 to 1440 minutes")
	case b.BanMinutes < 1 || b.BanMinutes > 525600:
		return bad("brute", "the ban lasts 1 to 525600 minutes")
	case b.PermanentAfter < 0 || b.PermanentAfter > 100:
		return bad("brute", "permanent after 0 (never) to 100 bans")
	}
	for _, s := range b.Sources {
		if !slices.Contains(Sources, s) {
			return bad("brute", fmt.Sprintf("%q is not a source: ssh, mail, ftp or panel", s))
		}
	}
	if c.Enabled && c.Policy == "closed" {
		for _, need := range []struct {
			port int
			what string
		}{{panelPort, "the panel"}, {c.SSHPort, "SSH"}} {
			if need.port > 0 && !c.PortOpen(need.port, "tcp") {
				return bad("ports", fmt.Sprintf("a closed firewall must keep port %d open: it is %s", need.port, need.what))
			}
		}
	}
	return nil
}

// EnqueueApply queues the job that gives the agent the rules, unless one
// is waiting already.
func EnqueueApply(ctx context.Context, q *jobs.Queue, createdBy string) (string, error) {
	id, err := q.Enqueue(ctx, JobApply, struct{}{}, jobs.EnqueueOptions{LockKey: "firewall", Unique: true, MaxAttempts: 3, CreatedBy: createdBy})
	if errors.Is(err, jobs.ErrDuplicate) {
		return "", nil
	}
	return id, err
}
