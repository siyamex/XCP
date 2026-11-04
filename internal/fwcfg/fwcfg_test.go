package fwcfg

import (
	"net/netip"
	"testing"
)

func TestDefaultNormalizes(t *testing.T) {
	c := Default(2443)
	if err := c.Normalize(2443); err != nil {
		t.Fatal(err)
	}
	if !c.PortOpen(2443, "tcp") || !c.PortOpen(22, "tcp") || c.PortOpen(3306, "tcp") {
		t.Errorf("ports: %+v", c.Ports)
	}
}

func TestClosedPolicyKeepsPanelAndSSH(t *testing.T) {
	c := Default(2443)
	c.Enabled, c.Policy, c.Ports = true, "closed", []Port{{Port: "80", Proto: "tcp"}}
	if err := c.Normalize(2443); err == nil {
		t.Error("a closed firewall without the panel's and SSH's ports was accepted")
	}
	c.Ports = append(c.Ports, Port{Port: "22", Proto: "tcp"}, Port{Port: "2400-2500", Proto: "tcp"})
	if err := c.Normalize(2443); err != nil {
		t.Errorf("ranges should keep the panel port open: %v", err)
	}
}

func TestNormalizeRefuses(t *testing.T) {
	mut := map[string]func(*Config){
		"policy":     func(c *Config) { c.Policy = "maybe" },
		"ssh port":   func(c *Config) { c.SSHPort = 70000 },
		"port":       func(c *Config) { c.Ports = []Port{{Port: "80; drop", Proto: "tcp"}} },
		"proto":      func(c *Config) { c.Ports = []Port{{Port: "80", Proto: "sctp"}} },
		"allow":      func(c *Config) { c.Allow = []Entry{{CIDR: "nope"}} },
		"deny":       func(c *Config) { c.Deny = []Entry{{CIDR: "1.2.3.4/99"}} },
		"service":    func(c *Config) { c.Restrict = map[string][]string{"mysql": {"192.0.2.1"}} },
		"restrict":   func(c *Config) { c.Restrict = map[string][]string{"panel": {"x"}} },
		"threshold":  func(c *Config) { c.Brute.Threshold = 0 },
		"source":     func(c *Config) { c.Brute.Sources = []string{"telnet"} },
		"rate":       func(c *Config) { c.Rate.Enabled = true; c.Rate.PerMinute = 0 },
		"ban length": func(c *Config) { c.Brute.BanMinutes = -1 },
	}
	for name, f := range mut {
		c := Default(2443)
		f(&c)
		if err := c.Normalize(2443); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestContains(t *testing.T) {
	list := []string{"192.0.2.0/24", "2001:db8::/32"}
	for ip, want := range map[string]bool{"192.0.2.77": true, "192.0.3.1": false, "2001:db8::1": true, "2001:db9::1": false} {
		if got := Contains(list, netip.MustParseAddr(ip)); got != want {
			t.Errorf("Contains(%s) = %v", ip, got)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.5": "192.0.2.5/32", "192.0.2.0/24": "192.0.2.0/24", "2001:db8::1": "2001:db8::1/128", "::ffff:192.0.2.5": "192.0.2.5/32"} {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseCIDR(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "x", "1.2.3.4/33", "1.2.3.4; drop"} {
		if _, err := ParseCIDR(in); err == nil {
			t.Errorf("ParseCIDR(%q) accepted", in)
		}
	}
}
