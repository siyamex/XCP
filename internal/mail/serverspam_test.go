package mail_test

import (
	"testing"

	"github.com/siyamex/XCP/internal/mail"
)

func TestServerSpamSettings(t *testing.T) {
	e := newEnv(t)
	cur, err := e.svc.Settings(ctx, e.admin)
	if err != nil {
		t.Fatal(err)
	}
	if cur.SpamReject != 15 || len(cur.SpamAllow) != 0 || len(cur.SpamBlock) != 0 {
		t.Errorf("defaults: %+v", cur)
	}
	in := mail.SettingsInput{
		Hostname: cur.Hostname, MaxMessageMB: cur.MaxMessageMB, SpamReject: 25,
		SpamAllow: []string{" Partner.Example ", "partner.example"}, SpamBlock: []string{"Bad@Spam.example", "evil.example", ""},
	}
	got, jobID, err := e.svc.SaveSettings(ctx, client, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if got.SpamReject != 25 || len(got.SpamAllow) != 1 || got.SpamAllow[0] != "partner.example" || len(got.SpamBlock) != 2 || got.SpamBlock[0] != "bad@spam.example" {
		t.Errorf("saved: %+v", got)
	}
	s := e.fake.MailSettings()
	if s == nil || s.SpamReject != 25 || len(s.SpamBlock) != 2 || len(s.SpamAllow) != 1 {
		t.Errorf("the agent got %+v", s)
	}
	for name, mut := range map[string]func(*mail.SettingsInput){
		"reject low":    func(i *mail.SettingsInput) { i.SpamReject = 2 },
		"reject high":   func(i *mail.SettingsInput) { i.SpamReject = 1000 },
		"allow address": func(i *mail.SettingsInput) { i.SpamAllow = []string{"a@b.example"} },
		"block junk":    func(i *mail.SettingsInput) { i.SpamBlock = []string{"x y"} },
	} {
		bad := in
		mut(&bad)
		if _, _, err := e.svc.SaveSettings(ctx, client, e.admin, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
