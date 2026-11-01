package agent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

const testArgon = "{ARGON2ID}$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA"

func testDKIM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func testMailAccount(t *testing.T) MailAccount {
	return MailAccount{Username: "alice", UID: 10001, GID: 10001, Domains: []MailDomain{
		{
			Name: "alice.example", Routing: MailLocal, DKIMKey: testDKIM(t),
			Mailboxes: []Mailbox{
				{Local: "info", PasswordHash: testArgon, QuotaMB: 500, Login: true, Receive: true, Send: true},
				{Local: "quiet", PasswordHash: testArgon, Login: false, Receive: false, Send: false},
			},
			Forwarders: []Forwarder{
				{Local: "info", To: []string{"boss@other.example"}},
				{Local: "sales", To: []string{"info@alice.example", "x@other.example"}},
				{Local: "old", Fail: "This address is no longer used"},
			},
			CatchAll: []string{"info@alice.example"},
		},
		{Name: "alias.example", Routing: MailLocal, AliasOf: "alice.example"},
		{Name: "backup.example", Routing: MailBackup},
	}}
}

func TestCheckMailAccount(t *testing.T) {
	if err := CheckMailAccount(testMailAccount(t)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MailAccount){
		"bad local":        func(a *MailAccount) { a.Domains[0].Mailboxes[0].Local = "Info" },
		"plain password":   func(a *MailAccount) { a.Domains[0].Mailboxes[0].PasswordHash = "secret" },
		"fail on mailbox":  func(a *MailAccount) { a.Domains[0].Forwarders[2].Local = "info" },
		"newline message":  func(a *MailAccount) { a.Domains[0].Forwarders[2].Fail = "a\nREJECT x" },
		"bad target":       func(a *MailAccount) { a.Domains[0].Forwarders[1].To = []string{"not an address"} },
		"alias with boxes": func(a *MailAccount) { a.Domains[1].Mailboxes = a.Domains[0].Mailboxes },
		"bad routing":      func(a *MailAccount) { a.Domains[2].Routing = "remote" },
		"low uid":          func(a *MailAccount) { a.UID = 0 },
		"short DKIM key": func(a *MailAccount) {
			a.Domains[0].DKIMKey = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
		},
	} {
		a := testMailAccount(t)
		mutate(&a)
		if err := CheckMailAccount(a); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: want invalid, got %v", name, err)
		}
	}
}

func TestRenderMail(t *testing.T) {
	f := renderMail([]MailAccount{testMailAccount(t)}, "/home")
	want := map[string][]string{
		"domains":       {"alice.example OK"},
		"alias_domains": {"alias.example OK"},
		"relay_domains": {"backup.example OK"},
		"mailboxes":     {"info@alice.example OK"},
		"aliases": {
			"info@alice.example info@alice.example, boss@other.example", // keeps a copy
			"sales@alice.example info@alice.example, x@other.example",
			"@alice.example info@alice.example",
			"@alias.example @alice.example",
		},
		"recipient_access": {"old@alice.example REJECT This address is no longer used", "quiet@alice.example REJECT This mailbox does not receive mail"},
		"sender_logins":    {"info@alice.example info@alice.example"},
		"sasl_access":      {"quiet@alice.example REJECT"},
	}
	for name, lines := range want {
		for _, l := range lines {
			if !strings.Contains(f.maps[name], l) {
				t.Errorf("%s lacks %q:\n%s", name, l, f.maps[name])
			}
		}
	}
	if strings.Contains(f.maps["mailboxes"], "quiet@") || strings.Contains(f.maps["domains"], "backup.example") {
		t.Error("a mailbox that does not receive, or a backup domain, is local")
	}
	if !strings.Contains(f.passwd, "info@alice.example:"+testArgon+":10001:10001::/home/alice/mail/alice.example/info::userdb_quota_rule=*:storage=500M\n") ||
		!strings.Contains(f.passwd, "quiet@alice.example:"+testArgon+":10001:10001::/home/alice/mail/alice.example/quiet::nologin=y\n") {
		t.Errorf("passwd:\n%s", f.passwd)
	}
	if _, ok := f.dkim["alice.example.xcp.key"]; !ok || !strings.Contains(f.dkimMap, "alice.example xcp") {
		t.Error("DKIM key not written")
	}
}

func TestMailSettings(t *testing.T) {
	s := MailSettings{
		Hostname: "mail.example.com", MaxMessageMB: 50, RBLs: []string{"zen.spamhaus.org"}, HeloChecks: true,
		RelayHost: "smtp.relay.example:2525", RelayUser: "u", RelayPassword: "p@ss",
	}
	if err := CheckMailSettings(s); err != nil {
		t.Fatal(err)
	}
	cf := renderMainCF(s, "/c.crt", "/c.key")
	for _, want := range []string{
		"myhostname = mail.example.com\n", "message_size_limit = 52428800\n", "relayhost = [smtp.relay.example]:2525\n",
		"reject_rbl_client zen.spamhaus.org", "reject_non_fqdn_helo_hostname", "smtpd_tls_cert_file = /c.crt\n",
		"virtual_transport = lmtp:unix:private/dovecot-lmtp\n", "smtp_sasl_auth_enable = yes\n",
	} {
		if !strings.Contains(cf, want) {
			t.Errorf("main.cf lacks %q", want)
		}
	}
	for _, bad := range []MailSettings{
		{Hostname: "x y", MaxMessageMB: 50},
		{Hostname: "mail.example.com", MaxMessageMB: 0},
		{Hostname: "mail.example.com", MaxMessageMB: 50, RelayHost: "relay;rm", RelayUser: "", RelayPassword: ""},
		{Hostname: "mail.example.com", MaxMessageMB: 50, RelayUser: "u", RelayPassword: "p"}, // no host
		{Hostname: "mail.example.com", MaxMessageMB: 50, RelayHost: "r.example", RelayUser: "u", RelayPassword: "a b"},
	} {
		if err := CheckMailSettings(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%+v: want invalid, got %v", bad, err)
		}
	}
}
