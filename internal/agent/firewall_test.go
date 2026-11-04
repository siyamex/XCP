package agent

import (
	"strings"
	"testing"
)

func TestFirewallRender(t *testing.T) {
	r := FirewallRules{
		Enabled: true, Closed: true,
		OpenPorts: []FWPort{{"22", "tcp"}, {"443", "tcp"}, {"30000-30999", "tcp"}, {"53", "udp"}},
		Allow:     []string{"192.0.2.10/32", "2001:db8:1::/48"},
		Deny:      []string{"198.51.100.0/24"},
		Bans:      []FWBan{{"203.0.113.9", 3600}, {"203.0.113.10", 0}, {"2001:db8::9", 60}},
		Restrictions: []FWRestriction{
			{Name: "panel", Ports: []FWPort{{"2443", "tcp"}}, Allowed: []string{"192.0.2.0/24", "2001:db8:2::/48"}},
		},
		RateEnabled: true, RatePerMin: 100, RatePorts: []FWPort{{"22", "tcp"}},
	}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	got := r.Render()
	for _, want := range []string{
		"table inet xcp",
		"delete table inet xcp",
		"192.0.2.10/32", "2001:db8:1::/48", "198.51.100.0/24",
		"203.0.113.9 timeout 3600s", "203.0.113.10", "2001:db8::9 timeout 60s",
		"30000-30999", "2443",
		"hook input priority -10",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%s", want, got)
		}
	}
	// A permanent ban has no timeout.
	if strings.Contains(got, "203.0.113.10 timeout") {
		t.Error("a permanent ban got a timeout")
	}
	// Closed ends with a drop; open does not.
	if !strings.Contains(got, "drop") {
		t.Error("closed policy never drops")
	}
	open := FirewallRules{Enabled: true, OpenPorts: r.OpenPorts}
	if strings.Contains(open.Render(), "\n\t\tdrop\n") {
		t.Errorf("open policy ends with a catch-all drop:\n%s", open.Render())
	}
}

func TestFirewallCheckRefuses(t *testing.T) {
	bad := []FirewallRules{
		{Enabled: true, OpenPorts: []FWPort{{"0; flush ruleset", "tcp"}}},
		{Enabled: true, OpenPorts: []FWPort{{"22", "icmp"}}},
		{Enabled: true, Allow: []string{"203.0.113.1; drop"}},
		{Enabled: true, Deny: []string{"not-an-address"}},
		{Enabled: true, Bans: []FWBan{{"203.0.113.1\nflush ruleset", 10}}},
		{Enabled: true, Bans: []FWBan{{"203.0.113.1", -5}}},
		{Enabled: true, Restrictions: []FWRestriction{{Name: "x y", Ports: []FWPort{{"22", "tcp"}}, Allowed: []string{"192.0.2.1"}}}},
		{Enabled: true, RateEnabled: true, RatePerMin: 0},
	}
	for i, r := range bad {
		if err := r.Check(); err == nil {
			t.Errorf("rules %d accepted: %+v", i, r)
		}
	}
}
