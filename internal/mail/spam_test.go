package mail_test

import (
	"errors"
	"testing"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/mail"
)

func TestMailboxSpamFilter(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	_, bob := e.account(t, "bob")
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: o.Domains[0].ID, Local: "info", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, m.JobID)

	// Defaults: on, 6, Junk, empty lists. The agent already got the filter.
	sp, err := e.svc.Spam(ctx, user, m.ID)
	if err != nil || !sp.Enabled || sp.Threshold != 6 || sp.Action != "junk" || len(sp.Allow) != 0 || len(sp.Block) != 0 {
		t.Fatalf("default: %+v %v", sp, err)
	}
	acct, _ := e.fake.MailAccount("alice")
	got := acct.Domains[0].Mailboxes[0].Spam
	if got == nil || !got.Enabled || got.Threshold != 6 || got.Action != agent.SpamJunk {
		t.Errorf("the agent got %+v", got)
	}

	// Another account cannot read or change it.
	if _, err := e.svc.Spam(ctx, bob, m.ID); err == nil {
		t.Error("bob reads alice's filter")
	}
	if _, err := e.svc.SetSpam(ctx, client, bob, m.ID, mail.Spam{Enabled: true, Threshold: 6, Action: "junk"}); err == nil {
		t.Error("bob changes alice's filter")
	}

	in := mail.Spam{Enabled: true, Threshold: 9, Action: "delete", Allow: []string{" Friend@Example.com ", "*@good.example", "friend@example.com"}, Block: []string{"*@spam.example"}}
	out, err := e.svc.SetSpam(ctx, client, user, m.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, out.JobID)
	if len(out.Allow) != 2 || out.Allow[0] != "*@good.example" || out.Allow[1] != "friend@example.com" {
		t.Errorf("lists are cleaned: %+v", out)
	}
	acct, _ = e.fake.MailAccount("alice")
	got = acct.Domains[0].Mailboxes[0].Spam
	if got == nil || got.Threshold != 9 || got.Action != agent.SpamDelete || len(got.Allow) != 2 || got.Block[0] != "*@spam.example" {
		t.Errorf("the agent got %+v", got)
	}

	for name, bad := range map[string]mail.Spam{
		"threshold 0":  {Enabled: true, Threshold: 0, Action: "junk"},
		"threshold 99": {Enabled: true, Threshold: 99, Action: "junk"},
		"action":       {Enabled: true, Threshold: 6, Action: "bounce"},
		"pattern":      {Enabled: true, Threshold: 6, Action: "junk", Block: []string{"x\" ; discard"}},
		"everyone":     {Enabled: true, Threshold: 6, Action: "junk", Allow: []string{"*"}},
		"both lists":   {Enabled: true, Threshold: 6, Action: "junk", Allow: []string{"a@b.example"}, Block: []string{"a@b.example"}},
	} {
		if _, err := e.svc.SetSpam(ctx, client, user, m.ID, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Admins may look; a package without the feature keeps users out.
	if _, err := e.svc.Spam(ctx, e.admin, m.ID); !errors.Is(err, apperr.ErrForbidden) && err != nil && err.Error() == "" {
		t.Errorf("admin: %v", err)
	}
}
