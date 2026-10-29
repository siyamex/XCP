package validate

import (
	"errors"
	"testing"
)

func TestDocRoot(t *testing.T) {
	ok := map[string]string{
		"public_html":           "public_html",
		"/public_html/shop/":    "public_html/shop",
		"domains/shop.example":  "domains/shop.example",
		" sites/a_b/www-1 ":     "sites/a_b/www-1",
		"Public_HTML":           "Public_HTML",
		"domains/x.example.com": "domains/x.example.com",
	}
	for in, want := range ok {
		if got, err := DocRoot(in); err != nil || got != want {
			t.Errorf("DocRoot(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "/", ".", "..", "a/../b", "public_html/..", ".ssh", "public_html/.git", "tmp", "TMP/x", "mail/cur",
		"etc", "a b", "a\\b", "a//b", "-x", "a/b/c/d/e/f/g/h/i", "a\nb", "a\"b", "a$b",
	} {
		if got, err := DocRoot(bad); err == nil {
			t.Errorf("DocRoot(%q) = %q, want an error", bad, got)
		}
	}
}

func TestRedirectPathAndTarget(t *testing.T) {
	for in, want := range map[string]string{"": "/", "/": "/", "/old": "/old", "/a/b-c_d.html/": "/a/b-c_d.html"} {
		if got, err := RedirectPath(in); err != nil || got != want {
			t.Errorf("RedirectPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"old", "/a b", "/a/../b", "/a/./b", "/a\"b", "/$1", "/a?b", "//", "/.well-known", "/.well-known/acme-challenge/x"} {
		if _, err := RedirectPath(bad); err == nil {
			t.Errorf("RedirectPath(%q) accepted", bad)
		}
	}
	for _, good := range []string{
		"https://example.com", "http://example.com/new/page?x=1&y=2#top", "https://203.0.113.5:8443/a",
		"https://xn--bcher-kva.example/p%C3%A4th", "https://[2001:db8::1]/",
	} {
		if got, err := RedirectTarget(good); err != nil || got != good {
			t.Errorf("RedirectTarget(%q) = %q, %v", good, got, err)
		}
	}
	for _, bad := range []string{
		"", "example.com", "/relative", "ftp://example.com", "javascript:alert(1)", "https://user:pw@example.com/",
		"https://example.com/a b", `https://example.com/"x`, `https://example.com/\x`, "https://example.com/$1",
		"https://example.com/\nRedirect 301 / http://evil", "https://", "https://-bad-.example/",
		"https://example.com/'x",
	} {
		if _, err := RedirectTarget(bad); err == nil {
			t.Errorf("RedirectTarget(%q) accepted", bad)
		}
	}
	for _, c := range []int{301, 302, 307, 308} {
		if RedirectCode(c) != nil {
			t.Errorf("code %d refused", c)
		}
	}
	if err := RedirectCode(200); !errors.Is(err, ErrValidation) {
		t.Errorf("code 200: %v", err)
	}
}

func TestSubdomainLabelAndRegistrable(t *testing.T) {
	for in, want := range map[string]string{"blog": "blog", " Shop ": "shop", "a.b": "a.b", "*": "*", "x-1.": "x-1"} {
		if got, err := SubdomainLabel(in); err != nil || got != want {
			t.Errorf("SubdomainLabel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-a", "a_b", "*.blog", "a..b", "a b", "ä"} {
		if _, err := SubdomainLabel(bad); err == nil {
			t.Errorf("SubdomainLabel(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"example.com": "example.com", "shop.example.com": "example.com", "*.example.co.uk": "example.co.uk",
		"a.b.example.co.uk": "example.co.uk",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
}
