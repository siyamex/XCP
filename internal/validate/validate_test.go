package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestUsername(t *testing.T) {
	for _, ok := range []string{"alice", "a", "bob2024", "abcdefghijklmnop"} {
		if err := Username(ok); err != nil {
			t.Errorf("Username(%q) = %v", ok, err)
		}
	}
	bad := map[string]string{
		"":                  CodeRequired,
		"abcdefghijklmnopq": CodeTooLong,
		"Alice":             CodeFormat,
		"1abc":              CodeFormat,
		"al_ice":            CodeFormat,
		"al-ice":            CodeFormat,
		"al ice":            CodeFormat,
		"root":              CodeReserved,
		"test":              CodeReserved,
		"xcp":               CodeReserved,
	}
	for in, code := range bad {
		var ve *Error
		if err := Username(in); !errors.As(err, &ve) || ve.Code != code {
			t.Errorf("Username(%q) = %v, want code %s", in, err, code)
		}
	}
}

func TestErrorWithFieldAndIs(t *testing.T) {
	err := WithField(Username(""), "username")
	if !errors.Is(err, ErrValidation) || err.Error() != "username: username is required" {
		t.Fatalf("err = %v", err)
	}
	plain := errors.New("x")
	if WithField(plain, "f") != plain {
		t.Fatal("WithField must not wrap non-validation errors")
	}
}

func TestPassword(t *testing.T) {
	if err := Password("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"short", strings.Repeat("x", MaxPasswordLen+1), "with\nnewline-123", "nul\x00byte-1234"} {
		if Password(bad) == nil {
			t.Errorf("Password(%q) accepted", bad)
		}
	}
}

func TestIPAndCIDR(t *testing.T) {
	if a, err := IP("::ffff:192.0.2.1"); err != nil || a.String() != "192.0.2.1" {
		t.Errorf("IP unmapped = %v, %v", a, err)
	}
	for _, bad := range []string{"", "1.2.3", "fe80::1%eth0", "example.com", "1.2.3.4/24"} {
		if _, err := IP(bad); err == nil {
			t.Errorf("IP(%q) accepted", bad)
		}
	}
	cases := map[string]string{
		"203.0.113.77/24": "203.0.113.0/24",
		"203.0.113.7":     "203.0.113.7/32",
		"2001:db8::1":     "2001:db8::1/128",
		" 2001:db8::/32 ": "2001:db8::/32",
	}
	for in, want := range cases {
		if p, err := CIDR(in); err != nil || p.String() != want {
			t.Errorf("CIDR(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"1.2.3.4/33", "x/8", "1.2.3.4/"} {
		if _, err := CIDR(bad); err == nil {
			t.Errorf("CIDR(%q) accepted", bad)
		}
	}
}

func TestPortAndRelPath(t *testing.T) {
	if Port(0) == nil || Port(65536) == nil || Port(443) != nil {
		t.Error("Port bounds wrong")
	}
	if p, err := RelPath("public_html//a/"); err != nil || p != "public_html/a" {
		t.Errorf("RelPath = %q, %v", p, err)
	}
	if _, err := RelPath("../etc"); !errors.Is(err, ErrValidation) {
		t.Errorf("RelPath(../etc) err = %v", err)
	}
}

func TestCron(t *testing.T) {
	ok := map[string]string{
		"*/15  *  * * *": "*/15 * * * *",
		"0 3 * * 1-5":    "0 3 * * 1-5",
		"@daily":         "@daily",
	}
	for in, want := range ok {
		if got, err := CronSchedule(in); err != nil || got != want {
			t.Errorf("CronSchedule(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "* * * *", "61 * * * *", "@every 1m", "@reboot", "* * * * * *"} {
		if _, err := CronSchedule(bad); err == nil {
			t.Errorf("CronSchedule(%q) accepted", bad)
		}
	}
	if _, err := CronCommand("php ~/cron.php\n* * * * * evil"); err == nil {
		t.Error("CronCommand accepted a line break (crontab injection)")
	}
	if c, err := CronCommand("  /usr/bin/php -q ~/x.php  "); err != nil || c != "/usr/bin/php -q ~/x.php" {
		t.Errorf("CronCommand = %q, %v", c, err)
	}
}

func FuzzUsername(f *testing.F) {
	for _, s := range []string{"alice", "root", "1a", "a-b", "ÄBC"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if Username(s) != nil {
			return
		}
		if len(s) == 0 || len(s) > 16 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatalf("accepted unsafe username %q", s)
		}
	})
}

func FuzzCronCommand(f *testing.F) {
	f.Add("php ~/cron.php")
	f.Add("a\nb")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := CronCommand(s)
		if err == nil && strings.ContainsAny(c, "\x00\r\n") {
			t.Fatalf("accepted multi-line command %q", c)
		}
	})
}
