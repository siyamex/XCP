package messages

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

// runNotices sends the queued notices as the worker would and returns how many.
func runNotices(t *testing.T, e *env) int {
	t.Helper()
	n := 0
	for {
		j, err := e.svc.jobs.Claim(ctx, "test", []string{JobNotice}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if j == nil {
			return n
		}
		res, err := e.svc.noticeJob(ctx, j, nopReporter{})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.jobs.Complete(ctx, j.ID, "test", res); err != nil {
			t.Fatal(err)
		}
		n++
	}
}

func TestNoticeTemplates(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller(t, "reseller1")
	list, err := e.svc.Notices(ctx, r1)
	if err != nil || len(list) != len(NoticeKinds) || list[0].Kind != NoticeSuspended || list[0].Custom {
		t.Fatalf("%+v %v", list, err)
	}
	if _, err := e.svc.SetNotice(ctx, client, e.admin, NoticeDiskFull, "Disk is full on {{domain}}", "Used {{used}} of {{limit}}"); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.noticeTemplate(ctx, r1.Login.ID, NoticeDiskFull); got.Custom || got.Subject != "Disk is full on {{domain}}" {
		t.Errorf("the reseller does not inherit the admin text: %+v", got)
	}
	if got, err := e.svc.SetNotice(ctx, client, r1, NoticeDiskFull, "Mine", "Mine {{percent}}"); err != nil || !got.Custom {
		t.Fatalf("%+v %v", got, err)
	}
	if got := e.svc.noticeTemplate(ctx, "", NoticeDiskFull); got.Subject != "Disk is full on {{domain}}" {
		t.Errorf("the reseller changed the admin text: %+v", got)
	}
	if got, _ := e.svc.SetNotice(ctx, client, r1, NoticeDiskFull, "", ""); got.Custom || got.Subject != "Disk is full on {{domain}}" {
		t.Errorf("reset: %+v", got)
	}
	if _, err := e.svc.SetNotice(ctx, client, e.admin, "nope", "a", "b"); err == nil {
		t.Error("an unknown notice")
	}
	if _, err := e.svc.SetNotice(ctx, client, e.admin, NoticeSuspended, "x", "{{password}}"); err == nil {
		t.Error("an unknown variable")
	}
}

func TestSuspensionNotices(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller(t, "reseller1")
	a := e.account(t, "alice", r1.Login.ID, "alice@customer.example")
	none := e.account(t, "bob", "", "")

	e.svc.AccountEvent(ctx, a, NoticeSuspended, "payment is overdue")
	e.svc.AccountEvent(ctx, none, NoticeSuspended, "x") // no address: nothing queued
	if n := runNotices(t, e); n != 1 {
		t.Fatalf("queued %d notices", n)
	}
	m := e.mail.out[0]
	if m.to != "alice@customer.example" || !strings.Contains(m.subject, "suspended") || !strings.Contains(m.body, "payment is overdue") || !strings.Contains(m.body, "reseller1") {
		t.Errorf("%+v", m)
	}
	e.svc.AccountEvent(ctx, a, NoticeUnsuspended, "")
	runNotices(t, e)
	if len(e.mail.out) != 2 || !strings.Contains(e.mail.out[1].subject, "active again") {
		t.Errorf("%+v", e.mail.out)
	}
	// A suspension without a reason says so; the admin can switch notices off.
	e.svc.AccountEvent(ctx, a, NoticeSuspended, "")
	runNotices(t, e)
	if !strings.Contains(e.mail.out[2].body, "no reason was given") {
		t.Errorf("%q", e.mail.out[2].body)
	}
	if err := e.db.SetSetting(ctx, settingEnabled, false); err != nil {
		t.Fatal(err)
	}
	e.svc.AccountEvent(ctx, a, NoticeSuspended, "x")
	if n := runNotices(t, e); n != 0 {
		t.Errorf("notices are off but %d were queued", n)
	}
}

func TestUsageNotices(t *testing.T) {
	e := newEnv(t)
	e.svc.UsePlans(plans.NewService(e.db, audit.NewRecorder(e.db)))
	disk := map[string]int64{}
	e.svc.UseDisk(func(context.Context) (map[string]int64, error) { return disk, nil })
	// The default package: 10 GiB of disk, 100 GiB of traffic a month.
	const gib = int64(1) << 30
	e.account(t, "alice", "", "alice@customer.example")
	b := e.account(t, "bob", "", "bob@customer.example")
	run := func() int {
		if _, err := e.svc.usageJob(ctx, &jobs.Job{}, nopReporter{}); err != nil {
			t.Fatal(err)
		}
		return runNotices(t, e)
	}
	last := func() sent { return e.mail.out[len(e.mail.out)-1] }

	disk["alice"] = 7 * gib
	if n := run(); n != 0 {
		t.Fatalf("%d notices under 80%%", n)
	}
	disk["alice"] = 9 * gib
	if n := run(); n != 1 || !strings.Contains(last().subject, "90%") || !strings.Contains(last().body, "9.0 GiB of 10.0 GiB") {
		t.Fatalf("warning: %d %+v", n, e.mail.out)
	}
	if n := run(); n != 0 {
		t.Errorf("the warning was sent twice: %d", n)
	}
	disk["alice"] = 10 * gib
	if n := run(); n != 1 || !strings.Contains(last().subject, "full") {
		t.Fatalf("full: %d %+v", n, e.mail.out)
	}
	if n := run(); n != 0 {
		t.Errorf("the full notice was sent twice: %d", n)
	}
	// After the use drops below the warning share, a new rise is news again.
	disk["alice"] = 1 * gib
	run()
	disk["alice"] = 9 * gib
	if n := run(); n != 1 {
		t.Errorf("a new warning after a drop: %d", n)
	}

	// Traffic: once a month, of this month only.
	day := e.now.Format(time.DateOnly)
	if err := store.AddUsage(ctx, e.db.W, b.ID, store.Usage{Domain: "bob.example", Day: day, Web: 90 * gib}); err != nil {
		t.Fatal(err)
	}
	if n := run(); n != 1 || !strings.Contains(last().subject, "traffic") || last().to != "bob@customer.example" {
		t.Fatalf("traffic warning: %d %+v", n, e.mail.out)
	}
	if n := run(); n != 0 {
		t.Errorf("the traffic warning was sent twice: %d", n)
	}
	e.now = e.now.AddDate(0, 1, 0)
	if n := run(); n != 0 {
		t.Errorf("last month's traffic counted: %d", n)
	}
	// The admin's share counts.
	if err := e.db.SetSetting(ctx, settingPercent, 95); err != nil {
		t.Fatal(err)
	}
	disk["alice"] = 1 * gib
	run()
	disk["alice"] = 9 * gib
	if n := run(); n != 0 {
		t.Errorf("90%% is below the 95%% the admin set: %d", n)
	}
}
