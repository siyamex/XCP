package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestDomain(t *testing.T) {
	ok := map[string]string{
		"example.com":        "example.com",
		"Example.COM.":       "example.com",
		" shop.example.com ": "shop.example.com",
		"bücher.de":          "xn--bcher-kva.de",
		"straße.de":          "xn--strae-oqa.de", // IDNA2008: ß is kept, not mapped to ss
		"example.co.uk":      "example.co.uk",
		"a-b.example.org":    "a-b.example.org",
		"xn--bcher-kva.de":   "xn--bcher-kva.de",
		"my-site.test":       "my-site.test",
	}
	for in, want := range ok {
		if got, err := Domain(in); err != nil || got != want {
			t.Errorf("Domain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"":                                       CodeRequired,
		"localhost":                              CodeFormat,
		"com":                                    CodeFormat,
		"co.uk":                                  CodePublicSuffix,
		"github.io":                              CodePublicSuffix,
		"-bad.com":                               CodeFormat,
		"bad-.com":                               CodeFormat,
		"under_score.com":                        CodeFormat,
		"sp ace.com":                             CodeFormat,
		"1.2.3.4":                                CodeFormat,
		"a..b.com":                               CodeFormat,
		"example.com/path":                       CodeFormat,
		"evil.com\n":                             "", // trimmed, then fine — newline must not survive
		strings.Repeat("a", 64) + ".com":         CodeFormat,
		strings.Repeat("abcdefghi.", 26) + "com": CodeTooLong,
	}
	for in, code := range bad {
		got, err := Domain(in)
		if code == "" {
			if strings.ContainsAny(got, "\r\n") {
				t.Errorf("Domain(%q) kept a line break: %q", in, got)
			}
			continue
		}
		var ve *Error
		if !errors.As(err, &ve) || ve.Code != code {
			t.Errorf("Domain(%q) = %q, %v; want code %s", in, got, err, code)
		}
	}
}

func TestWildcardAndHelpers(t *testing.T) {
	if got, err := WildcardDomain("*.Example.com"); err != nil || got != "*.example.com" {
		t.Errorf("WildcardDomain = %q, %v", got, err)
	}
	if _, err := WildcardDomain("*.*.example.com"); err == nil {
		t.Error("double wildcard accepted")
	}
	if _, err := WildcardDomain("a.*.example.com"); err == nil {
		t.Error("inner wildcard accepted")
	}
	if got := DomainUnicode("xn--bcher-kva.de"); got != "bücher.de" {
		t.Errorf("DomainUnicode = %q", got)
	}
	if !IsSubdomainOf("a.example.com", "example.com") || IsSubdomainOf("badexample.com", "example.com") {
		t.Error("IsSubdomainOf wrong")
	}
}

func TestMailboxAndEmail(t *testing.T) {
	if got, err := MailboxName("Info.Sales"); err != nil || got != "info.sales" {
		t.Errorf("MailboxName = %q, %v", got, err)
	}
	for _, bad := range []string{"", "a+b", ".a", "a.", "a..b", "a b", "a|b", `"a"`, strings.Repeat("a", 65)} {
		if _, err := MailboxName(bad); err == nil {
			t.Errorf("MailboxName(%q) accepted", bad)
		}
	}
	if got, err := Email("John+Hosting@Bücher.DE"); err != nil || got != "john+hosting@xn--bcher-kva.de" {
		t.Errorf("Email = %q, %v", got, err)
	}
	for _, bad := range []string{"", "a@", "@b.com", "a@b", "a b@c.com", "a|b@c.com", "a@b@c.com", `"a"@b.com`, "a..b@c.com", "a@co.uk"} {
		if _, err := Email(bad); err == nil {
			t.Errorf("Email(%q) accepted", bad)
		}
	}
}

func FuzzDomain(f *testing.F) {
	for _, s := range []string{"example.com", "bücher.de", "co.uk", "*.a.com", "a..b", "xn--", "1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := Domain(s)
		if err != nil {
			return
		}
		if len(d) > MaxDomainLen || strings.Trim(d, "abcdefghijklmnopqrstuvwxyz0123456789-.") != "" ||
			strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
			t.Fatalf("Domain(%q) = %q is not a safe LDH name", s, d)
		}
		if again, err := Domain(d); err != nil || again != d {
			t.Fatalf("Domain not idempotent: %q -> %q -> %q, %v", s, d, again, err)
		}
	})
}

func FuzzEmail(f *testing.F) {
	for _, s := range []string{"a@example.com", "a+b@x.org", "a|b@x.org", "\"q\"@x.org"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := Email(s)
		if err != nil {
			return
		}
		if strings.ContainsAny(e, " \t\r\n\x00\"'|,;:<>()[]\\") || strings.Count(e, "@") != 1 {
			t.Fatalf("Email(%q) = %q contains unsafe characters", s, e)
		}
	})
}
