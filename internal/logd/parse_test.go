package logd

import (
	"testing"
	"time"
)

func TestAddWeb(t *testing.T) {
	s := Sums{}
	for _, l := range []string{
		`example.com:443 192.0.2.1 - - [02/Nov/2026:10:00:00 +0500] "GET / HTTP/1.1" 200 510 "-" "agent"`,
		`Example.COM:80 192.0.2.1 - - [02/Nov/2026:10:00:01 +0500] "GET /a\"b HTTP/1.1" 404 1000 "-" "a \"quoted\" agent"`,
		`example.com:80 192.0.2.1 - - [02/Nov/2026:04:59:59 +0500] "GET / HTTP/1.1" 200 7 "-" "-"`, // 23:59:59 UTC the day before
		`shop.example.org:443 ::1 - - [02/Nov/2026:10:00:02 +0000] "POST /x HTTP/2.0" 201 20 "-" "-"`,
	} {
		if !s.AddWeb([]byte(l)) {
			t.Errorf("not parsed: %s", l)
		}
	}
	for _, bad := range []string{
		``, `garbage`, `example.com:80 1.2.3.4 - - [bad date] "GET /" 200 5`,
		`example.com:80 1.2.3.4 - - [02/Nov/2026:10:00:00 +0500] "GET / HTTP/1.1" 408 -`,
		`example.com:80 1.2.3.4 - - [02/Nov/2026:10:00:00 +0500] "GET / HTTP/1.1`,
	} {
		if s.AddWeb([]byte(bad)) {
			t.Errorf("parsed: %q", bad)
		}
	}
	want := map[Key]Counts{
		{"example.com", "2026-11-02"}:      {Web: 1510},
		{"example.com", "2026-11-01"}:      {Web: 7},
		{"shop.example.org", "2026-11-02"}: {Web: 20},
	}
	check(t, s, want)
}

func check(t *testing.T, s Sums, want map[Key]Counts) {
	t.Helper()
	if len(s) != len(want) {
		t.Errorf("got %d keys, want %d", len(s), len(want))
	}
	for k, w := range want {
		if g := s[k]; g == nil || *g != w {
			t.Errorf("%v: got %+v, want %+v", k, g, w)
		}
	}
}

func TestAddFTP(t *testing.T) {
	s := Sums{}
	utc := time.UTC
	for _, l := range []string{
		"Mon Nov 02 10:00:23 2026 0 127.0.0.1 15 /home/ftp1/public_html/shop/hello.txt b _ i r web@ftp1.example ftp 1 * c",
		"Mon Nov 02 10:00:24 2026 1 192.0.2.9 1000 /home/ftp1/public_html/a file with spaces.zip b _ o r web@ftp1.example ftp 1 * c",
	} {
		if !s.AddFTP([]byte(l), utc) {
			t.Errorf("not parsed: %s", l)
		}
	}
	for _, bad := range []string{
		"", "Mon Nov 02 10:00:23 2026 0 127.0.0.1 x /f b _ i r web@a.example ftp 1 * c",
		"Mon Nov 02 10:00:23 2026 0 127.0.0.1 5 /f b _ i r nodomain ftp 1 * c",
	} {
		if s.AddFTP([]byte(bad), utc) {
			t.Errorf("parsed: %q", bad)
		}
	}
	check(t, s, map[Key]Counts{{"ftp1.example", "2026-11-02"}: {FTP: 1015}})
}

func TestMail(t *testing.T) {
	s := Sums{}
	var m Mail
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	for _, l := range []string{
		// Incoming to a mailbox here.
		"66FC5FA99: client=mx.example.net[192.0.2.1]",
		"66FC5FA99: from=<someone@example.org>, size=513, nrcpt=2 (queue active)",
		"66FC5FA99: to=<info@a.example>, relay=panel.example[private/dovecot-lmtp], delay=0.3, dsn=2.0.0, status=sent (250 2.0.0 Saved)",
		"66FC5FA99: to=<sales@b.example>, relay=panel.example[private/dovecot-lmtp], delay=0.3, dsn=2.0.0, status=sent (250 2.0.0 Saved)",
		"66FC5FA99: removed",
		// Sent by a mailbox user to another server.
		"D9C3AFB8D: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=sender@a.example",
		"D9C3AFB8D: from=<sender@a.example>, size=1000, nrcpt=1 (queue active)",
		"D9C3AFB8D: to=<x@example.net>, relay=mx.example.net[192.0.2.2]:25, delay=1, dsn=2.0.0, status=sent (250 ok)",
		// Forwarded: counts for the forwarding domain.
		"AA2E9FB75: from=<someone@example.org>, size=300, nrcpt=1 (queue active)",
		"AA2E9FB75: to=<boss@example.net>, orig_to=<fwd@c.example>, relay=mx.example.net[192.0.2.2]:25, delay=1, dsn=2.0.0, status=sent (250 ok)",
		// Bounced: nothing.
		"80F78FA95: from=<sender@a.example>, size=999, nrcpt=1 (queue active)",
		"80F78FA95: to=<x@nowhere.example>, relay=none, delay=538, dsn=5.4.4, status=bounced (Host not found)",
		// Not about a message.
		"connect from localhost[127.0.0.1]",
		"warning: hostname x does not resolve",
	} {
		m.Line(s, l, at)
	}
	check(t, s, map[Key]Counts{
		{"a.example", "2026-11-02"}: {Mail: 513 + 1000},
		{"b.example", "2026-11-02"}: {Mail: 513},
		{"c.example", "2026-11-02"}: {Mail: 300},
	})
	if _, ok := m.q["66FC5FA99"]; ok {
		t.Error("a removed message is still followed")
	}
}
