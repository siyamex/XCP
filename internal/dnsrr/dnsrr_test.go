package dnsrr

import (
	"errors"
	"strings"
	"testing"

	"github.com/siyamex/XCP/internal/validate"
)

const zone = "example.com"

func TestName(t *testing.T) {
	ok := map[string]string{
		"":                  "example.com",
		"@":                 "example.com",
		"example.com.":      "example.com",
		"WWW":               "www.example.com",
		"www.example.com":   "www.example.com",
		"_dmarc":            "_dmarc.example.com",
		"_sip._tcp":         "_sip._tcp.example.com",
		"*":                 "*.example.com",
		"*.blog":            "*.blog.example.com",
		"a.b.c.example.com": "a.b.c.example.com",
	}
	for in, want := range ok {
		if got, err := Name(in, zone); err != nil || got != want {
			t.Errorf("Name(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"a b", "-a", "a..b", "blog.*", "ü", "a/b", strings.Repeat("a", 64), "x\nevil"} {
		if got, err := Name(bad, zone); err == nil {
			t.Errorf("Name(%q) = %q, want an error", bad, got)
		}
	}
	if Relative("example.com", zone) != "@" || Relative("www.example.com", zone) != "www" {
		t.Fatal("Relative")
	}
}

func TestContent(t *testing.T) {
	ok := []struct{ typ, in, want string }{
		{"A", " 192.0.2.10 ", "192.0.2.10"},
		{"AAAA", "2001:DB8::1", "2001:db8::1"},
		{"CNAME", "mail.example.net", "mail.example.net."},
		{"CNAME", "@", "example.com."},
		{"MX", "10   mail.example.com", "10 mail.example.com."},
		{"MX", "20 mail", "20 mail.example.com."},
		{"CNAME", "www", "www.example.com."},
		{"SRV", "0 0 443 @", "0 0 443 example.com."},
		{"MX", "0 .", "0 ."},
		{"NS", "ns1.provider.net.", "ns1.provider.net."},
		{"SRV", "10 5 5060 sip.example.com", "10 5 5060 sip.example.com."},
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		{"TLSA", "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"HTTPS", `1 . alpn="h2,h3"`, `1 . alpn="h2,h3"`},
		{"TXT", "v=spf1 a mx ~all", `"v=spf1 a mx ~all"`},
		{"TXT", `v=DMARC1; p=none; say "hi"`, `"v=DMARC1; p=none; say \"hi\""`},
	}
	for _, c := range ok {
		got, err := Content(c.typ, c.in, zone)
		if err != nil || got != c.want {
			t.Errorf("Content(%s, %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
			continue
		}
		if back := Plain(c.typ, got); c.typ == "TXT" && back != c.in {
			t.Errorf("Plain(%q) = %q, want %q", got, back, c.in)
		}
	}
	for _, c := range []struct{ typ, in string }{
		{"A", "2001:db8::1"},
		{"A", "300.1.1.1"},
		{"A", ""},
		{"AAAA", "192.0.2.1"},
		{"CNAME", "192.0.2.1"},
		{"CNAME", "."},
		{"MX", "mail.example.com"},
		{"MX", "10 192.0.2.1"},
		{"MX", "10 ."},
		{"NS", "."},
		{"CAA", `0 bogus "x"`},
		{"SOA", "a. b. 1 2 3 4 5"},
		{"PTR", "x.example.com"},
		{"A", "192.0.2.1 ; comment"},
		{"A", "192.0.2.1\n$INCLUDE /etc/passwd"},
		{"MX", "10 a.example.com) (x"},
		{"TXT", ""},
		{"TXT", "bad\x00byte"},
		{"TXT", strings.Repeat("x", 4001)},
	} {
		if got, err := Content(c.typ, c.in, zone); !errors.Is(err, validate.ErrValidation) {
			t.Errorf("Content(%s, %q) = %q, %v; want a validation error", c.typ, c.in, got, err)
		}
	}
}

func TestLongTXTIsSplitBetweenCharacters(t *testing.T) {
	long := strings.Repeat("ü", 200) // 400 bytes: must not be cut inside a character
	got, err := Content("TXT", long, zone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, `" "`) != 1 || Plain("TXT", got) != long {
		t.Fatalf("split = %q", got)
	}
	if err := Check(zone, Record{Name: zone, Type: "TXT", TTL: 3600, Content: got}); err != nil {
		t.Fatalf("agent refuses the API's own TXT: %v", err)
	}
}

func TestCheckZone(t *testing.T) {
	rec := func(name, typ, content string) Record {
		return Record{Name: name, Type: typ, TTL: 3600, Content: content}
	}
	good := []Record{
		rec("example.com", "A", "192.0.2.10"),
		rec("www.example.com", "CNAME", "example.com."),
		rec("example.com", "MX", "10 mail.example.com."),
		rec("example.com", "TXT", `"v=spf1 a mx ~all"`),
		rec("sub.example.com", "NS", "ns1.other.net."),
	}
	if err := CheckZone(zone, good); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]Record{
		"cname with others":  {rec("www.example.com", "CNAME", "example.com."), rec("www.example.com", "A", "192.0.2.1")},
		"cname at top":       {rec("example.com", "CNAME", "other.net.")},
		"apex ns":            {rec("example.com", "NS", "ns1.other.net.")},
		"outside the zone":   {rec("example.net", "A", "192.0.2.1")},
		"lookalike zone":     {rec("badexample.com", "A", "192.0.2.1")},
		"not normalised":     {rec("example.com", "MX", "10 mail.example.com")},
		"unquoted txt":       {rec("example.com", "TXT", "v=spf1")},
		"twice":              {rec("example.com", "A", "192.0.2.1"), rec("example.com", "A", "192.0.2.1")},
		"ttl too short":      {{Name: "example.com", Type: "A", TTL: 5, Content: "192.0.2.1"}},
		"upper case name":    {rec("WWW.example.com", "A", "192.0.2.1")},
		"soa from the panel": {rec("example.com", "SOA", "ns1.example.com. hostmaster.example.com. 1 2 3 4 5")},
	}
	for name, rs := range bad {
		if err := CheckZone(zone, rs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckZone("Example.com", nil); err == nil {
		t.Error("unnormalised zone name accepted")
	}
}
