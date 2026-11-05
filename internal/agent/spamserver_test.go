package agent

import (
	"strings"
	"testing"
)

func TestSpamServerSettings(t *testing.T) {
	good := MailSettings{Hostname: "mail.example.com", MaxMessageMB: 50, SpamReject: 20, SpamAllow: []string{"partner.example"}, SpamBlock: []string{"bad@spam.example", "evil.example"}}
	if err := CheckMailSettings(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*MailSettings){
		"reject too low":  func(s *MailSettings) { s.SpamReject = 3 },
		"reject too high": func(s *MailSettings) { s.SpamReject = 500 },
		"allow address":   func(s *MailSettings) { s.SpamAllow = []string{"a@b.example"} },
		"allow upper":     func(s *MailSettings) { s.SpamAllow = []string{"Partner.example"} },
		"block junk":      func(s *MailSettings) { s.SpamBlock = []string{"x y"} },
		"block injection": func(s *MailSettings) { s.SpamBlock = []string{"a@b.example\n.*"} },
		"block upper":     func(s *MailSettings) { s.SpamBlock = []string{"Bad@Spam.example"} },
	} {
		s := good
		mut(&s)
		if CheckMailSettings(s) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// 0 is the default.
	d := good
	d.SpamReject = 0
	if err := CheckMailSettings(d); err != nil {
		t.Errorf("default reject: %v", err)
	}
}

func TestSpamServerFiles(t *testing.T) {
	if got := RspamdActions(0); !strings.Contains(got, "reject = 15;") {
		t.Errorf("default: %s", got)
	}
	if got := RspamdActions(30); !strings.Contains(got, "reject = 30;") {
		t.Errorf("30: %s", got)
	}
	if got := mapFile([]string{"b.example", "a.example"}); got != "a.example\nb.example\n" {
		t.Errorf("map: %q", got)
	}
	if mapFile(nil) != "# empty\n" {
		t.Error("an empty map must still be a valid file")
	}
	if !strings.Contains(rspamdWhitelist("/m"), "valid_dkim = true;") || !strings.Contains(rspamdMultimap("/m"), "score = 20.0;") {
		t.Error("whitelist needs a signature; the block list outweighs the refusal limit")
	}
}
