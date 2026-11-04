package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/siyamex/XCP/internal/execx"
)

// Firewall runs XCP's nftables table (ADR-0017): its own table "inet xcp"
// with allow, deny and ban sets, so nothing else's rules are touched.
type Firewall struct {
	Run  *execx.Runner
	Bin  string // /usr/sbin/nft; missing means nftables is not installed
	File string // /etc/xcp/firewall.nft: loaded again at boot by xcp-firewall.service
	mu   sync.Mutex
}

// Paths of the firewall setup made by xcp-install.
const (
	NftPath      = "/usr/sbin/nft"
	FirewallFile = "/etc/xcp/firewall.nft"
	fwMaxEntries = 20000
	fwMaxBans    = 200000
)

// FWPort is a port or range of a protocol.
type FWPort struct {
	Port, Proto string
}

// FWBan bans one address; Seconds 0 is for good.
type FWBan struct {
	IP      string
	Seconds int64
}

// FWRestriction lets only the Allowed networks reach the ports.
type FWRestriction struct {
	Name    string
	Ports   []FWPort
	Allowed []string
}

// FirewallRules is the firewall to run. Enabled false removes it.
type FirewallRules struct {
	Enabled      bool
	Closed       bool // only OpenPorts are let in
	OpenPorts    []FWPort
	Allow, Deny  []string
	Bans         []FWBan
	Restrictions []FWRestriction
	RateEnabled  bool
	RatePerMin   int
	RatePorts    []FWPort
}

var fwPortRe = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)

func checkFWPort(p FWPort) error {
	if p.Proto != "tcp" && p.Proto != "udp" {
		return invalid("firewall port %q: the protocol is tcp or udp", p.Port)
	}
	if !fwPortRe.MatchString(p.Port) {
		return invalid("firewall port %q is not a port or range", p.Port)
	}
	lo, hi, _ := strings.Cut(p.Port, "-")
	a, _ := strconv.Atoi(lo)
	b := a
	if hi != "" {
		b, _ = strconv.Atoi(hi)
	}
	if a < 1 || b > 65535 || a > b {
		return invalid("firewall port %q is out of range", p.Port)
	}
	return nil
}

func checkPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Masked() != p {
		return p, invalid("%q is not a network in its canonical form (like 203.0.113.0/24)", s)
	}
	return p, nil
}

// Check validates the rules: every address and port is parsed, nothing
// is passed to nft as text that was not.
func (r FirewallRules) Check() error {
	if len(r.Allow)+len(r.Deny) > fwMaxEntries || len(r.Bans) > fwMaxBans {
		return invalid("too many firewall entries")
	}
	for _, list := range [][]string{r.Allow, r.Deny} {
		for _, s := range list {
			if _, err := checkPrefix(s); err != nil {
				return err
			}
		}
	}
	for _, b := range r.Bans {
		a, err := netip.ParseAddr(b.IP)
		if err != nil || a.Unmap() != a || b.Seconds < 0 {
			return invalid("%q is not a single address to ban", b.IP)
		}
	}
	ports := slices.Concat(r.OpenPorts, r.RatePorts)
	for _, rs := range r.Restrictions {
		if !slices.Contains([]string{"panel", "ssh", "ftp"}, rs.Name) {
			return invalid("%q is not a service to restrict", rs.Name)
		}
		ports = append(ports, rs.Ports...)
		for _, s := range rs.Allowed {
			if _, err := checkPrefix(s); err != nil {
				return err
			}
		}
	}
	for _, p := range ports {
		if err := checkFWPort(p); err != nil {
			return err
		}
	}
	if r.RateEnabled && (r.RatePerMin < 1 || r.RatePerMin > 1_000_000) {
		return invalid("rate limit out of range")
	}
	return nil
}

func split(list []string) (v4, v6 []string) {
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Addr().Is4() {
				v4 = append(v4, s)
			} else {
				v6 = append(v6, s)
			}
		}
	}
	return v4, v6
}

func fwSet(b *strings.Builder, name, typ, flags string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags %s\n", name, typ, flags)
	if flags == "interval" {
		b.WriteString("\t\tauto-merge\n")
	}
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

// portList renders ports of one protocol as "22, 30000-30999", or "" if none.
func portList(ports []FWPort, proto string) string {
	var out []string
	for _, p := range ports {
		if p.Proto == proto {
			out = append(out, p.Port)
		}
	}
	return strings.Join(out, ", ")
}

// Render writes the nft script of the rules: it replaces the table in one
// step. The order matters: loopback, the allow list (let in whatever else
// says), bans and the deny list, then what is already connected, then the
// restrictions and the rate limit, then (closed) the open ports.
func (r FirewallRules) Render() string {
	a4, a6 := split(r.Allow)
	d4, d6 := split(r.Deny)
	var b4, b6 []string
	for _, b := range r.Bans {
		el := b.IP
		if b.Seconds > 0 {
			el += " timeout " + strconv.FormatInt(b.Seconds, 10) + "s"
		}
		if a, _ := netip.ParseAddr(b.IP); a.Is4() {
			b4 = append(b4, el)
		} else {
			b6 = append(b6, el)
		}
	}
	var s strings.Builder
	s.WriteString("# Managed by XCP (ADR-0017). Changes are overwritten.\ntable inet xcp\ndelete table inet xcp\ntable inet xcp {\n")
	fwSet(&s, "allow4", "ipv4_addr", "interval", a4)
	fwSet(&s, "allow6", "ipv6_addr", "interval", a6)
	fwSet(&s, "deny4", "ipv4_addr", "interval", d4)
	fwSet(&s, "deny6", "ipv6_addr", "interval", d6)
	fwSet(&s, "ban4", "ipv4_addr", "timeout", b4)
	fwSet(&s, "ban6", "ipv6_addr", "timeout", b6)
	s.WriteString("\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
	s.WriteString("\t\tiifname \"lo\" accept\n")
	s.WriteString("\t\tip saddr @allow4 accept\n\t\tip6 saddr @allow6 accept\n")
	s.WriteString("\t\tip saddr @deny4 drop\n\t\tip6 saddr @deny6 drop\n\t\tip saddr @ban4 drop\n\t\tip6 saddr @ban6 drop\n")
	s.WriteString("\t\tct state established,related accept\n")
	for _, rs := range r.Restrictions {
		al4, al6 := split(rs.Allowed)
		for _, proto := range []string{"tcp", "udp"} {
			ports := portList(rs.Ports, proto)
			if ports == "" || len(rs.Allowed) == 0 {
				continue
			}
			if len(al4) > 0 {
				fmt.Fprintf(&s, "\t\tmeta nfproto ipv4 %s dport { %s } ip saddr != { %s } drop\n", proto, ports, strings.Join(al4, ", "))
			} else {
				fmt.Fprintf(&s, "\t\tmeta nfproto ipv4 %s dport { %s } drop\n", proto, ports)
			}
			if len(al6) > 0 {
				fmt.Fprintf(&s, "\t\tmeta nfproto ipv6 %s dport { %s } ip6 saddr != { %s } drop\n", proto, ports, strings.Join(al6, ", "))
			} else {
				fmt.Fprintf(&s, "\t\tmeta nfproto ipv6 %s dport { %s } drop\n", proto, ports)
			}
		}
	}
	if ports := portList(r.RatePorts, "tcp"); r.RateEnabled && ports != "" {
		fmt.Fprintf(&s, "\t\ttcp dport { %s } ct state new meter xcp_rate4 { ip saddr timeout 5m limit rate over %d/minute } drop\n", ports, r.RatePerMin)
		fmt.Fprintf(&s, "\t\ttcp dport { %s } ct state new meter xcp_rate6 { ip6 saddr timeout 5m limit rate over %d/minute } drop\n", ports, r.RatePerMin)
	}
	if r.Closed {
		s.WriteString("\t\tip protocol icmp accept\n\t\tip6 nexthdr icmpv6 accept\n")
		if t := portList(r.OpenPorts, "tcp"); t != "" {
			fmt.Fprintf(&s, "\t\ttcp dport { %s } accept\n", t)
		}
		if u := portList(r.OpenPorts, "udp"); u != "" {
			fmt.Fprintf(&s, "\t\tudp dport { %s } accept\n", u)
		}
		s.WriteString("\t\tdrop\n")
	}
	s.WriteString("\t}\n}\n")
	return s.String()
}

func (f *Firewall) installed() error {
	if _, err := os.Stat(f.Bin); err != nil {
		return fmt.Errorf("nftables is not installed: %w", ErrNotInstalled)
	}
	return nil
}

// run runs nft, with a script on its standard input.
func (f *Firewall) run(ctx context.Context, script string, args ...string) (execx.Result, error) {
	cmd := execx.Cmd{Path: f.Bin, Args: args}
	if script != "" {
		cmd.Stdin = strings.NewReader(script)
	}
	return f.Run.Run(ctx, cmd)
}

// tableExists reports whether our table is loaded.
func (f *Firewall) tableExists(ctx context.Context) bool {
	_, err := f.run(ctx, "", "list", "table", "inet", "xcp")
	return err == nil
}

// Apply loads the rules, or removes the table when they are not enabled.
// A script nft refuses is refused before anything changes. It reports
// whether anything changed.
func (f *Firewall) Apply(ctx context.Context, r FirewallRules) (bool, error) {
	if err := r.Check(); err != nil {
		return false, err
	}
	if err := f.installed(); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, name := filepath.Dir(f.File), filepath.Base(f.File)
	if !r.Enabled {
		existed := f.tableExists(ctx)
		if existed {
			if _, err := f.run(ctx, "", "delete", "table", "inet", "xcp"); err != nil {
				return false, err
			}
		}
		wrote, err := writeFile(dir, name, "# XCP's firewall is off (ADR-0017).\n", 0o600, "")
		return existed || wrote, err
	}
	script := r.Render()
	if res, err := f.run(ctx, script, "-c", "-f", "-"); err != nil {
		var ee *execx.ExitError
		if errors.As(err, &ee) {
			return false, invalid("nftables refused the firewall: %s", strings.TrimSpace(string(res.Stderr)))
		}
		return false, err
	}
	if res, err := f.run(ctx, script, "-f", "-"); err != nil {
		return false, fmt.Errorf("load the firewall: %w: %s", err, strings.TrimSpace(string(res.Stderr)))
	}
	if _, err := writeFile(dir, name, script, 0o600, ""); err != nil {
		return true, err
	}
	return true, nil
}
