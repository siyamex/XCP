package mail_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/mail"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

const pw = "correct horse battery"

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

// dns is a fixed public DNS for the deliverability check.
type dns struct {
	txt  map[string][]string
	mx   map[string][]*net.MX
	host map[string][]string
	ptr  map[string][]string
}

func (d dns) LookupTXT(_ context.Context, n string) ([]string, error) { return d.txt[n], nil }
func (d dns) LookupMX(_ context.Context, n string) ([]*net.MX, error) { return d.mx[n], nil }
func (d dns) LookupHost(_ context.Context, n string) ([]string, error) {
	return d.host[n], nil
}
func (d dns) LookupAddr(_ context.Context, a string) ([]string, error) { return d.ptr[a], nil }

type host string

func (h host) Hostname(context.Context) string { return string(h) }

type env struct {
	svc   *mail.Service
	accts *accounts.Service
	zones *zones.Service
	plans *plans.Service
	db    *store.DB
	q     *jobs.Queue
	fake  *agentrpc.Fake
	dns   dns
	admin *auth.Principal
	pkgID string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	rec := audit.NewRecorder(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour,
		Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	l, err := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	admin := &auth.Principal{Login: l, Session: &store.Session{}}
	pkgs, _ := pl.ListPackages(ctx, admin)
	fake := agentrpc.NewFake()
	q := jobs.NewQueue(db)
	zs := zones.NewService(db, rec, pl, q, fake, zones.StaticHosts{})
	if err := zs.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	set, err := zs.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	set.Nameservers, set.IPv4, set.IPv6 = []string{"ns1.host.example", "ns2.host.example"}, "203.0.113.5", ""
	if _, _, err := zs.SaveSettings(ctx, client, admin, set); err != nil {
		t.Fatal(err)
	}
	doms := domains.NewService(db, rec, pl, q, fake, zs, domains.StaticTXT{}, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, zs)
	d := dns{txt: map[string][]string{}, mx: map[string][]*net.MX{}, host: map[string][]string{}, ptr: map[string][]string{}}
	svc := mail.NewService(db, rec, pl, q, fake, zs, box, d, host("mail.host.example"))
	accts.Attach("mail", svc)
	hook := func(ctx context.Context, tx *sql.Tx, by, accountID string) error {
		_, err := svc.EnqueueApply(ctx, tx, by, accountID)
		return err
	}
	doms.SetMailHook(hook)
	zs.SetMailHook(hook)
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	for _, r := range []interface{ RegisterJobs(*jobs.Worker) }{accts, doms, zs, svc} {
		r.RegisterJobs(w)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, accts: accts, zones: zs, plans: pl, db: db, q: q, fake: fake, dns: d, admin: admin, pkgID: pkgs[0].ID}
}

func (e *env) account(t *testing.T, user string) (accounts.Account, *auth.Principal) {
	t.Helper()
	a, err := e.accts.Create(ctx, client, e.admin, accounts.CreateInput{Username: user, Domain: user + ".example", PackageID: e.pkgID, Password: pw})
	if err != nil {
		t.Fatalf("create %s: %v", user, err)
	}
	e.waitJob(t, a.JobID)
	l, err := e.db.AccountLogin(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return a, &auth.Principal{Login: l, Session: &store.Session{}}
}

func (e *env) waitJob(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := e.q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			if j.Status == jobs.StatusFailed {
				t.Fatalf("job %s (%s) failed: %s", id, j.Kind, j.Error)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
	}
}

func conflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func field(err error, name string) bool {
	var ve *validate.Error
	return errors.As(err, &ve) && ve.Field == name
}

func TestMailLifecycle(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil || len(o.Domains) != 1 || o.Domains[0].Routing != store.MailLocal || o.Server != "mail.host.example" {
		t.Fatalf("overview: %+v %v", o, err)
	}
	dom := o.Domains[0].ID

	m, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "Info", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, m.JobID)
	if m.Address != "info@alice.example" || m.QuotaMB != 5*1024 {
		t.Fatalf("mailbox %+v: the package's largest quota by default", m)
	}
	got, ok := e.fake.MailAccount("alice")
	if !ok || len(got.Domains) != 1 || got.Domains[0].DKIMKey == "" || len(got.Domains[0].Mailboxes) != 1 ||
		!strings.HasPrefix(got.Domains[0].Mailboxes[0].PasswordHash, "{ARGON2ID}$argon2id$v=19$m=65536,t=2,p=1$") {
		t.Fatalf("mail in the agent: %+v", got)
	}
	// The DKIM key is published in the domain's zone.
	zs, _ := store.AccountZones(ctx, e.db.R, a.ID)
	recs, _ := store.ZoneRecords(ctx, e.db.R, zs[0].ID)
	if !slices.ContainsFunc(recs, func(r store.ZoneRecord) bool { return r.Name == "xcp._domainkey.alice.example" && r.Type == "TXT" }) {
		t.Fatal("DKIM record not added to the zone")
	}

	if _, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "big", Password: pw, QuotaMB: 99999}); !field(err, "quota_mb") {
		t.Errorf("quota over the package's: %v", err)
	}
	if _, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "info", Password: pw}); !conflict(err, "address_taken") {
		t.Errorf("same address twice: %v", err)
	}
	f, err := e.svc.CreateForwarder(ctx, client, user, a.ID, mail.ForwarderInput{DomainID: dom, Local: "sales", To: []string{"Boss@Other.example"}})
	if err != nil || !slices.Equal(f.To, []string{"boss@other.example"}) {
		t.Fatalf("forwarder: %+v %v", f, err)
	}
	if _, err := e.svc.CreateForwarder(ctx, client, user, a.ID, mail.ForwarderInput{DomainID: dom, Local: "info", Fail: "gone"}); !conflict(err, "address_taken") {
		t.Errorf("rejecting a mailbox's address: %v", err)
	}
	fail, err := e.svc.CreateForwarder(ctx, client, user, a.ID, mail.ForwarderInput{DomainID: dom, Local: "old", Fail: "This address is no longer used"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "old", Password: pw}); !conflict(err, "address_taken") {
		t.Errorf("a mailbox on a rejecting address: %v", err)
	}
	jobID, err := e.svc.SetCatchAll(ctx, client, user, dom, []string{"info@alice.example"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	got, _ = e.fake.MailAccount("alice")
	d := got.Domains[0]
	if len(d.Forwarders) != 2 || !slices.Equal(d.CatchAll, []string{"info@alice.example"}) {
		t.Fatalf("forwarders and default address in the agent: %+v", d)
	}
	if jobID, err = e.svc.DeleteForwarder(ctx, client, user, fail.ID); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)

	// Switches, then suspension: the mailbox still receives but cannot log in or send.
	if _, err := e.svc.UpdateMailbox(ctx, client, user, m.ID, mail.MailboxUpdate{QuotaMB: 100, Login: true, Receive: true, Send: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.accts.Suspend(ctx, client, e.admin, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		got, _ := e.fake.MailAccount("alice")
		b := got.Domains[0].Mailboxes[0]
		return !b.Login && !b.Send && b.Receive && b.QuotaMB == 100
	})
	if _, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, ok := e.fake.MailAccount("alice"); return !ok })
}

func TestRoutingAndIsolation(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	b, bob := e.account(t, "bob")
	o, _ := e.svc.Overview(ctx, alice, a.ID)
	dom := o.Domains[0].ID
	if _, err := e.svc.Overview(ctx, bob, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's mail: %v", err)
	}
	if _, err := e.svc.CreateMailbox(ctx, client, bob, b.ID, mail.MailboxInput{DomainID: dom, Local: "x", Password: pw}); !field(err, "domain_id") {
		t.Errorf("bob adds a mailbox on alice's domain: %v", err)
	}
	// Mail handled elsewhere: the domain leaves this server's mail.
	if _, err := e.svc.CreateMailbox(ctx, client, alice, a.ID, mail.MailboxInput{DomainID: dom, Local: "info", Password: pw}); err != nil {
		t.Fatal(err)
	}
	zs, _ := store.AccountZones(ctx, e.db.R, a.ID)
	if _, err := e.zones.SetMailRouting(ctx, client, alice, zs[0].ID, store.MailRemote); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, ok := e.fake.MailAccount("alice"); return ok && len(got.Domains) == 0 })
}

func TestDeliverabilityAndRepair(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	o, _ := e.svc.Overview(ctx, user, a.ID)
	dom := o.Domains[0].ID
	m, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "info", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, m.JobID)
	// Public DNS: MX here, SPF without this server, no DKIM, no DMARC, PTR set.
	e.dns.mx["alice.example"] = []*net.MX{{Host: "mail.alice.example.", Pref: 10}}
	e.dns.host["mail.alice.example"] = []string{"203.0.113.5"}
	e.dns.host["alice.example"] = []string{"198.51.100.1"}
	e.dns.txt["alice.example"] = []string{"v=spf1 a ~all", "google-site-verification=x"}
	e.dns.ptr["203.0.113.5"] = []string{"mail.host.example."}
	e.dns.host["mail.host.example"] = []string{"203.0.113.5"}
	res, err := e.svc.Deliverability(ctx, user, dom)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, c := range res.Checks {
		status[c.Name] = c.Status
	}
	want := map[string]string{"mx": "ok", "spf": "error", "dkim": "error", "dmarc": "warning", "ptr": "ok"}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s = %s, want %s (%+v)", k, status[k], v, res.Checks)
		}
	}
	if !res.Repairable {
		t.Error("the zone is here: repairable")
	}
	// What the zone has is what public DNS shows once published.
	zs, _ := store.AccountZones(ctx, e.db.R, a.ID)
	recs, _ := store.ZoneRecords(ctx, e.db.R, zs[0].ID)
	for _, r := range recs {
		if r.Type == "TXT" {
			e.dns.txt[r.Name] = append(e.dns.txt[r.Name], strings.Join(strings.Split(strings.Trim(r.Content, `"`), `" "`), ""))
		}
	}
	e.dns.txt["alice.example"] = []string{"v=spf1 a mx ~all"}
	res, _ = e.svc.Deliverability(ctx, user, dom)
	for _, c := range res.Checks {
		if c.Status != "ok" {
			t.Errorf("after publishing the zone's records, %s = %s: %s", c.Name, c.Status, c.Detail)
		}
	}
	// Repair keeps SPF and DMARC the zone has, so nothing changes.
	changed, err := e.svc.Repair(ctx, client, user, dom)
	if err != nil || changed {
		t.Fatalf("repair of a complete zone: %v %v", changed, err)
	}
}

func TestSettings(t *testing.T) {
	e := newEnv(t)
	_, user := e.account(t, "alice")
	if _, err := e.svc.Settings(ctx, user); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("user reads mail settings: %v", err)
	}
	set, err := e.svc.Settings(ctx, e.admin)
	if err != nil || set.Hostname != "mail.host.example" || set.MaxMessageMB != 50 || !set.HeloChecks {
		t.Fatalf("defaults: %+v %v", set, err)
	}
	in := mail.SettingsInput{
		Hostname: "mx.host.example", MaxMessageMB: 25, RelayHost: "smtp.relay.example", RelayUser: "u",
		RelayPassword: "secret", RBLs: []string{"zen.spamhaus.org"}, Greylisting: true,
	}
	got, jobID, err := e.svc.SaveSettings(ctx, client, e.admin, in)
	if err != nil || !got.HasRelayPass {
		t.Fatalf("save: %+v %v", got, err)
	}
	e.waitJob(t, jobID)
	if s := e.fake.MailSettings(); s == nil || s.RelayPassword != "secret" || s.Hostname != "mx.host.example" || !s.Greylisting {
		t.Fatalf("agent got %+v", s)
	}
	// The stored password stays when the form leaves it empty.
	in.RelayPassword = ""
	if _, jobID, err = e.svc.SaveSettings(ctx, client, e.admin, in); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if s := e.fake.MailSettings(); s.RelayPassword != "secret" {
		t.Fatal("relay password lost")
	}
	in.MaxMessageMB = 0
	if _, _, err := e.svc.SaveSettings(ctx, client, e.admin, in); !field(err, "settings") {
		t.Errorf("bad settings: %v", err)
	}
}

func TestAutoresponderPipeWebmail(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	o, _ := e.svc.Overview(ctx, user, a.ID)
	dom := o.Domains[0].ID
	m, err := e.svc.CreateMailbox(ctx, client, user, a.ID, mail.MailboxInput{DomainID: dom, Local: "info", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, m.JobID)

	jobID, err := e.svc.SetAutoresponder(ctx, client, user, m.ID, mail.Autoresponder{Subject: "Away", Body: "Back soon.", Start: "2026-11-01", End: "2026-11-08"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	got, _ := e.fake.MailAccount("alice")
	if r := got.Domains[0].Mailboxes[0].Reply; r == nil || r.Subject != "Away" || r.Days != 1 || r.End != "2026-11-08" {
		t.Fatalf("autoresponder in the agent: %+v", r)
	}
	o, _ = e.svc.Overview(ctx, user, a.ID)
	if o.Mailboxes[0].Reply == nil || o.Mailboxes[0].Reply.Body != "Back soon." {
		t.Fatalf("overview: %+v", o.Mailboxes[0])
	}
	if _, err := e.svc.SetAutoresponder(ctx, client, user, m.ID, mail.Autoresponder{Subject: "x", Body: "y", Start: "2026-11-08", End: "2026-11-01"}); !field(err, "autoresponder") {
		t.Errorf("end before start: %v", err)
	}
	if jobID, err = e.svc.DeleteAutoresponder(ctx, client, user, m.ID); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if got, _ := e.fake.MailAccount("alice"); got.Domains[0].Mailboxes[0].Reply != nil {
		t.Fatal("autoresponder not removed")
	}

	f, err := e.svc.CreateForwarder(ctx, client, user, a.ID, mail.ForwarderInput{DomainID: dom, Local: "orders", Pipe: "bin/orders.php"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, f.JobID)
	got, _ = e.fake.MailAccount("alice")
	if fw := got.Domains[0].Forwarders; len(fw) != 1 || fw[0].Pipe != "bin/orders.php" {
		t.Fatalf("pipe in the agent: %+v", fw)
	}
	for _, bad := range []mail.ForwarderInput{
		{DomainID: dom, Local: "x", Pipe: "../../etc/passwd"},
		{DomainID: dom, Local: "y", Pipe: "/bin/sh"},
		{DomainID: dom, Local: "z", Pipe: "a.php", To: []string{"a@b.example"}},
	} {
		if _, err := e.svc.CreateForwarder(ctx, client, user, a.ID, bad); !field(err, "pipe") {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := e.svc.CreateForwarder(ctx, client, user, a.ID, mail.ForwarderInput{DomainID: dom, Local: "info", Pipe: "x.php"}); !conflict(err, "address_taken") {
		t.Errorf("pipe on a mailbox: %v", err)
	}

	ticket, err := e.svc.Webmail(ctx, client, user, m.ID)
	if err != nil || len(ticket) != 64 {
		t.Fatalf("webmail: %q %v", ticket, err)
	}
	if _, err := e.svc.UpdateMailbox(ctx, client, user, m.ID, mail.MailboxUpdate{Login: false, Receive: true, Send: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Webmail(ctx, client, user, m.ID); !conflict(err, "login_off") {
		t.Errorf("webmail with login off: %v", err)
	}
}
