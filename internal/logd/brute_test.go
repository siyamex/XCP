package logd

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseFailure(t *testing.T) {
	tests := []struct {
		unit, msg, ip, source string
	}{
		{"ssh.service", "Failed password for root from 203.0.113.9 port 51234 ssh2", "203.0.113.9", "ssh"},
		{"ssh.service", "Failed password for invalid user admin from 2001:db8::5 port 40000 ssh2", "2001:db8::5", "ssh"},
		{"ssh.service", "Invalid user test from 198.51.100.7 port 3333", "198.51.100.7", "ssh"},
		{"ssh.service", "Failed publickey for bob from 198.51.100.8 port 22 ssh2: RSA SHA256:abc", "198.51.100.8", "ssh"},
		{"ssh.service", "Disconnecting authenticating user root 192.0.2.4 port 22: Too many authentication failures [preauth]", "192.0.2.4", "ssh"},
		{"postfix@-.service", "warning: unknown[203.0.113.20]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.20", "mail"},
		{"postfix.service", "warning: unknown[2001:db8::7]: SASL PLAIN authentication failed: ", "2001:db8::7", "mail"},
		{"dovecot.service", "imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<a@b.test>, method=PLAIN, rip=203.0.113.30, lip=192.0.2.1, TLS", "203.0.113.30", "mail"},
		{"pure-ftpd.service", "(?@203.0.113.40) [WARNING] Authentication failed for user [alice]", "203.0.113.40", "ftp"},
		{"pure-ftpd.service", "(bob@::ffff:203.0.113.41) [WARNING] Authentication failed for user [bob]", "203.0.113.41", "ftp"},
	}
	for _, tt := range tests {
		f, ok := ParseFailure(tt.unit, tt.msg)
		if !ok || f.IP.String() != tt.ip || f.Source != tt.source {
			t.Errorf("%s %q = %v %v, want %s %s", tt.unit, tt.msg, f, ok, tt.ip, tt.source)
		}
	}
	for _, tt := range [][2]string{
		{"ssh.service", "Accepted password for root from 203.0.113.9 port 51234 ssh2"},
		{"ssh.service", "Failed password for root from not-an-address port 22 ssh2"},
		{"postfix.service", "connect from unknown[203.0.113.20]"},
		{"dovecot.service", "imap-login: Login: user=<a@b.test>, method=PLAIN, rip=203.0.113.30"},
		{"pure-ftpd.service", "(alice@203.0.113.40) [INFO] alice is now logged in"},
		{"cron.service", "Failed password for root from 203.0.113.9 port 1 ssh2"},
	} {
		if f, ok := ParseFailure(tt[0], tt[1]); ok {
			t.Errorf("%s %q counted as a failure: %v", tt[0], tt[1], f)
		}
	}
}

func TestDetector(t *testing.T) {
	var d Detector
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	win := 10 * time.Minute
	for i := range 2 {
		if d.Add(a, t0.Add(time.Duration(i)*time.Minute), 3, win) {
			t.Fatalf("banned after %d failures", i+1)
		}
	}
	if d.Add(b, t0.Add(3*time.Minute), 3, win) {
		t.Error("another address's failures count together")
	}
	if !d.Add(a, t0.Add(4*time.Minute), 3, win) {
		t.Error("third failure within the window did not trigger")
	}
	// The count starts again after a trigger.
	if d.Add(a, t0.Add(5*time.Minute), 3, win) {
		t.Error("count was not reset")
	}
	// Failures that fall out of the window do not add up.
	c := netip.MustParseAddr("203.0.113.3")
	d.Add(c, t0, 3, win)
	d.Add(c, t0.Add(1*time.Minute), 3, win)
	if d.Add(c, t0.Add(30*time.Minute), 3, win) {
		t.Error("old failures counted")
	}
}
