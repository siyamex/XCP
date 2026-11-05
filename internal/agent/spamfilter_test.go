package agent

import (
	"strings"
	"testing"
)

func TestCleanSpamPattern(t *testing.T) {
	for in, want := range map[string]string{"Friend@Example.COM": "friend@example.com", " *@example.com ": "*@example.com", "news*@list.example": "news*@list.example"} {
		got, err := CleanSpamPattern(in)
		if err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*", "**", "a b@c.example", "x@y\"z", "x@y.example\nBcc:", "nodomain", "a", "x;y@z.example", strings.Repeat("a", 101) + "@x"} {
		if _, err := CleanSpamPattern(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckSpamFilter(t *testing.T) {
	ok := SpamFilter{Enabled: true, Threshold: 6, Action: SpamJunk, Allow: []string{"a@b.example"}, Block: []string{"*@spam.example"}}
	if err := CheckSpamFilter(ok); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]SpamFilter{
		"threshold 0":   {Threshold: 0, Action: SpamJunk},
		"threshold 51":  {Threshold: 51, Action: SpamJunk},
		"action":        {Threshold: 6, Action: "bounce"},
		"unclean entry": {Threshold: 6, Action: SpamJunk, Block: []string{"Upper@Case.example"}},
	} {
		if CheckSpamFilter(f) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSpamSieve(t *testing.T) {
	s := SpamFilter{Enabled: true, Threshold: 8, Action: SpamJunk, Allow: []string{"friend@x.example"}, Block: []string{"*@spam.example", "bad@y.example"}}
	got := renderMailboxSieve("info@a.example", nil, &s)
	for _, want := range []string{
		`require ["fileinto", "mailbox"];`,
		`if address :matches :all "from" ["friend@x.example"] {`,
		`elsif address :matches :all "from" ["*@spam.example", "bad@y.example"] {`,
		`elsif header :contains "X-Spam-Level" "********" {`,
		`fileinto :create "Junk";`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "********* ") || strings.Contains(got, `"*********"`) {
		t.Errorf("threshold 8 is 8 stars:\n%s", got)
	}
	// Delete instead of Junk; no allow list: the block list opens the chain.
	s2 := SpamFilter{Enabled: true, Threshold: 5, Action: SpamDelete, Block: []string{"bad@y.example"}}
	got = renderMailboxSieve("info@a.example", nil, &s2)
	if !strings.Contains(got, "if address :matches :all \"from\" [\"bad@y.example\"] {\n  discard;") || strings.Contains(got, "fileinto :create") {
		t.Errorf("delete script:\n%s", got)
	}
	// Switched off: nothing about spam, only the requirement.
	off := renderMailboxSieve("info@a.example", nil, &SpamFilter{Enabled: false, Threshold: 6, Action: SpamJunk})
	if strings.Contains(off, "X-Spam-Level") || strings.Contains(off, "if ") {
		t.Errorf("a disabled filter still filters:\n%s", off)
	}
	// With an autoresponder both are in one script, one require.
	r := Autoresponder{Subject: "Away", Body: "Back soon", Days: 2}
	both := renderMailboxSieve("info@a.example", &r, &s)
	if strings.Count(both, "require ") != 1 || !strings.Contains(both, `"vacation"`) || !strings.Contains(both, "vacation :days 2") || !strings.Contains(both, "X-Spam-Level") {
		t.Errorf("combined script:\n%s", both)
	}
	// Without a spam filter the autoresponder script is what it always was.
	if renderMailboxSieve("info@a.example", &r, nil) != renderSieve("info@a.example", r) {
		t.Error("a mailbox without a spam filter got a different autoresponder script")
	}
	// Spam first: a spam message never gets an autoresponse.
	if strings.Index(both, "X-Spam-Level") > strings.Index(both, "vacation :days") {
		t.Errorf("the autoresponder runs before the spam filter:\n%s", both)
	}
}

func TestSpamMailRender(t *testing.T) {
	a := MailAccount{Username: "alice", UID: 10001, GID: 10001, Domains: []MailDomain{{
		Name: "a.example", Routing: MailLocal,
		Mailboxes: []Mailbox{
			{Local: "plain", PasswordHash: "x", Login: true, Receive: true, Send: true},
			{Local: "filtered", PasswordHash: "x", Login: true, Receive: true, Send: true, Spam: &SpamFilter{Enabled: true, Threshold: 6, Action: SpamJunk}},
		},
	}}}
	f := renderMail([]MailAccount{a}, "/home")
	if _, ok := f.sieve["a.example/plain.sieve"]; ok {
		t.Error("a mailbox with nothing to run got a script")
	}
	if s, ok := f.sieve["a.example/filtered.sieve"]; !ok || !strings.Contains(s.script, "X-Spam-Level") {
		t.Errorf("sieve: %+v", f.sieve)
	}
}
