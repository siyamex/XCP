package zones_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/jobs"
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

type env struct {
	svc   *zones.Service
	doms  *domains.Service
	accts *accounts.Service
	plans *plans.Service
	db    *store.DB
	fake  *agentrpc.Fake
	q     *jobs.Queue
	hosts zones.StaticHosts
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
	hosts := zones.StaticHosts{}
	svc := zones.NewService(db, rec, pl, q, fake, hosts)
	// Fixed settings, not the test machine's addresses.
	if err := db.SetSetting(ctx, "dns", zones.Settings{
		Nameservers: []string{"ns1.host.example", "ns2.host.example"}, IPv4: "192.0.2.10", IPv6: "2001:db8::10",
		TTL: 3600, Template: zones.DefaultTemplate(),
	}); err != nil {
		t.Fatal(err)
	}
	doms := domains.NewService(db, rec, pl, q, fake, svc, domains.StaticTXT{}, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, svc)
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	accts.RegisterJobs(w)
	doms.RegisterJobs(w)
	svc.RegisterJobs(w)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, doms: doms, accts: accts, plans: pl, db: db, fake: fake, q: q, hosts: hosts, admin: admin, pkgID: pkgs[0].ID}
}

func (e *env) account(t *testing.T, user, domain string) (accounts.Account, *auth.Principal) {
	t.Helper()
	a, err := e.accts.Create(ctx, client, e.admin, accounts.CreateInput{Username: user, Domain: domain, PackageID: e.pkgID, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, _ := e.accts.Get(ctx, e.admin, a.ID); return got.Status == store.AccountActive })
	l, err := e.db.AccountLogin(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return a, &auth.Principal{Login: l, Session: &store.Session{}}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// served returns the "name type content" lines the fake DNS server holds for a zone.
func (e *env) served(zone string) []string {
	z, ok := e.fake.Zone(zone)
	if !ok {
		return nil
	}
	var out []string
	for _, r := range z.Records {
		out = append(out, dnsrr.Relative(r.Name, zone)+" "+r.Type+" "+r.Content)
	}
	slices.Sort(out)
	return out
}

func (e *env) waitServed(t *testing.T, zone string, cond func([]string) bool) []string {
	t.Helper()
	var got []string
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got = e.served(zone); cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("zone %s: served %q", zone, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func has(lines ...string) func([]string) bool {
	return func(got []string) bool {
		for _, l := range lines {
			if !slices.Contains(got, l) {
				return false
			}
		}
		return true
	}
}

func lacks(lines ...string) func([]string) bool {
	return func(got []string) bool {
		for _, l := range lines {
			if slices.Contains(got, l) {
				return false
			}
		}
		return got != nil
	}
}

func (e *env) add(t *testing.T, accountID string, in domains.AddInput) domains.Domain {
	t.Helper()
	d, err := e.doms.Add(ctx, client, e.admin, accountID, in)
	if err != nil {
		t.Fatalf("add %+v: %v", in, err)
	}
	return d
}

func TestZonesFollowDomains(t *testing.T) {
	e := newEnv(t)
	a, _ := e.account(t, "alice", "example.com")
	got := e.waitServed(t, "example.com", func(s []string) bool { return len(s) > 0 })
	want := []string{
		`@ A 192.0.2.10`, `@ AAAA 2001:db8::10`, `@ MX 10 mail.example.com.`, `@ TXT "v=spf1 a mx ~all"`,
		`_dmarc TXT "v=DMARC1; p=none"`, `mail A 192.0.2.10`, `mail AAAA 2001:db8::10`, `www CNAME example.com.`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("new zone =\n%q\nwant\n%q", got, want)
	}
	if z, _ := e.fake.Zone("example.com"); !slices.Equal(z.Nameservers, []string{"ns1.host.example", "ns2.host.example"}) || z.Hostmaster != "hostmaster.example.com" {
		t.Fatalf("zone NS/SOA = %+v", z)
	}

	primary := e.mustDomains(t, a.ID)[0]
	blog := e.add(t, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "blog", ParentID: primary.ID})
	deep := e.add(t, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "deep.example.com"})
	e.waitServed(t, "example.com", has("blog A 192.0.2.10", "blog AAAA 2001:db8::10", "deep A 192.0.2.10", "www.deep CNAME deep.example.com."))
	shop := e.add(t, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "shop.net"})
	wild := e.add(t, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "*", ParentID: shop.ID})
	e.waitServed(t, "shop.net", has("@ A 192.0.2.10", "* A 192.0.2.10", "www CNAME shop.net."))
	if _, ok := e.fake.Zone("deep.example.com"); ok {
		t.Fatal("a domain inside the account's zone got a zone of its own")
	}

	for _, d := range []domains.Domain{blog, deep} {
		if _, err := e.doms.Delete(ctx, client, e.admin, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	e.waitServed(t, "example.com", lacks("blog A 192.0.2.10", "deep A 192.0.2.10", "www.deep CNAME deep.example.com."))
	if _, err := e.doms.Delete(ctx, client, e.admin, wild.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.doms.Delete(ctx, client, e.admin, shop.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, ok := e.fake.Zone("shop.net"); return !ok })

	tr, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = tr
	waitFor(t, func() bool { _, ok := e.fake.Zone("example.com"); return !ok })
	waitFor(t, func() bool { zs, _ := e.db.AllZones(ctx); return len(zs) == 0 })
}

func (e *env) mustDomains(t *testing.T, accountID string) []domains.Domain {
	t.Helper()
	ds, err := e.doms.List(ctx, e.admin, accountID)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func (e *env) zone(t *testing.T, p *auth.Principal, accountID string) zones.Zone {
	t.Helper()
	zs, err := e.svc.List(ctx, p, accountID, "")
	if err != nil || len(zs) == 0 {
		t.Fatalf("zones: %+v, %v", zs, err)
	}
	z, err := e.svc.Get(ctx, p, zs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func conflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func TestRecordEditor(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice", "example.com")
	z := e.zone(t, alice, a.ID)
	if z.MailRoutingEffective != store.MailLocal {
		t.Fatalf("template MX points here: routing = %q", z.MailRoutingEffective)
	}

	api, err := e.svc.AddRecord(ctx, client, alice, z.ID, zones.RecordInput{Name: "API", Type: "a", Content: "192.0.2.50"})
	if err != nil || api.Name != "api" || api.TTL != 3600 || api.JobID == "" {
		t.Fatalf("add = %+v, %v", api, err)
	}
	txt, err := e.svc.AddRecord(ctx, client, alice, z.ID, zones.RecordInput{Name: "_x", Type: "TXT", Content: `say "hi"`, TTL: 300})
	if err != nil || txt.Content != `say "hi"` {
		t.Fatalf("TXT = %+v, %v", txt, err)
	}
	e.waitServed(t, "example.com", has(`api A 192.0.2.50`, `_x TXT "say \"hi\""`))

	for name, in := range map[string]zones.RecordInput{
		"CNAME next to an A": {Name: "api", Type: "CNAME", Content: "other.net"},
		"CNAME at the top":   {Name: "@", Type: "CNAME", Content: "other.net"},
		"NS at the top":      {Name: "@", Type: "NS", Content: "ns.other.net"},
	} {
		if _, err := e.svc.AddRecord(ctx, client, alice, z.ID, in); !conflict(err, "record_conflict") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.AddRecord(ctx, client, alice, z.ID, zones.RecordInput{Name: "api", Type: "A", Content: "192.0.2.50"}); !conflict(err, "record_exists") {
		t.Errorf("duplicate: %v", err)
	}
	for _, in := range []zones.RecordInput{
		{Name: "a b", Type: "A", Content: "192.0.2.1"},
		{Name: "x", Type: "A", Content: "not an ip"},
		{Name: "x", Type: "SOA", Content: "a. b. 1 2 3 4 5"},
		{Name: "x", Type: "A", Content: "192.0.2.1", TTL: 5},
	} {
		if _, err := e.svc.AddRecord(ctx, client, alice, z.ID, in); !errors.Is(err, validate.ErrValidation) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	// Sub-delegation is fine below the top.
	if _, err := e.svc.AddRecord(ctx, client, alice, z.ID, zones.RecordInput{Name: "lab", Type: "NS", Content: "ns.other.net"}); err != nil {
		t.Fatal(err)
	}

	up, err := e.svc.UpdateRecord(ctx, client, alice, api.ID, zones.RecordInput{Name: "api", Type: "CNAME", Content: "example.net"})
	if err != nil || up.Content != "example.net." {
		t.Fatalf("update = %+v, %v", up, err)
	}
	e.waitServed(t, "example.com", has("api CNAME example.net."))
	jobID, err := e.svc.DeleteRecord(ctx, client, alice, api.ID)
	if err != nil || jobID == "" {
		t.Fatal(err)
	}
	e.waitServed(t, "example.com", lacks("api CNAME example.net."))

	// Mail at another provider: the routing follows the MX records.
	var mx zones.Record
	for _, r := range e.zone(t, alice, a.ID).Records {
		if r.Type == "MX" {
			mx = r
		}
	}
	if _, err := e.svc.UpdateRecord(ctx, client, alice, mx.ID, zones.RecordInput{Name: "@", Type: "MX", Content: "1 smtp.google.com"}); err != nil {
		t.Fatal(err)
	}
	if z := e.zone(t, alice, a.ID); z.MailRouting != store.MailAuto || z.MailRoutingEffective != store.MailRemote {
		t.Fatalf("routing = %q/%q", z.MailRouting, z.MailRoutingEffective)
	}
	if _, err := e.svc.AddRecord(ctx, client, alice, z.ID, zones.RecordInput{Name: "@", Type: "MX", Content: "20 mail"}); err != nil {
		t.Fatal(err)
	}
	if z := e.zone(t, alice, a.ID); z.MailRoutingEffective != store.MailBackup {
		t.Fatalf("lower-priority MX here: routing = %q", z.MailRoutingEffective)
	}
	if z, err := e.svc.SetMailRouting(ctx, client, alice, z.ID, store.MailLocal); err != nil || z.MailRoutingEffective != store.MailLocal {
		t.Fatalf("set routing: %+v, %v", z, err)
	}
	if _, err := e.svc.SetMailRouting(ctx, client, alice, z.ID, "elsewhere"); !errors.Is(err, validate.ErrValidation) {
		t.Fatalf("bad routing: %v", err)
	}
}

func TestZoneAccess(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice", "alice.example")
	b, bob := e.account(t, "bob", "bob.example")
	bz := e.zone(t, bob, b.ID)
	if _, err := e.svc.Get(ctx, alice, bz.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other account's zone: %v", err)
	}
	if zs, _ := e.svc.List(ctx, alice, b.ID, ""); len(zs) != 1 || zs[0].Name != "alice.example" {
		t.Fatalf("a user lists only their own zones: %+v", zs)
	}
	if all, _ := e.svc.List(ctx, e.admin, "", ""); len(all) != 2 {
		t.Fatalf("admin list = %+v", all)
	}
	if _, err := e.svc.GetSettings(ctx, alice); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("settings as a user: %v", err)
	}
	// Without the zone editor in the feature list.
	fl, _ := e.plans.SaveFeatureList(ctx, client, e.admin, "", plans.FeatureListInput{Name: "No DNS", Features: []string{"domains"}})
	pk, _ := e.plans.SavePackage(ctx, client, e.admin, "", plans.PackageInput{Name: "No DNS", FeatureListID: fl.ID, Limits: plans.DefaultLimits()})
	if _, err := e.accts.Update(ctx, client, e.admin, a.ID, accounts.UpdateInput{PackageID: pk.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.List(ctx, alice, a.ID, ""); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("zone editor without the feature: %v", err)
	}
}

func TestSettings(t *testing.T) {
	e := newEnv(t)
	e.account(t, "alice", "example.com")
	e.waitServed(t, "example.com", func(s []string) bool { return len(s) > 0 })
	e.hosts["ns1.host.example"] = []string{"192.0.2.10"}
	e.hosts["ns2.host.example"] = []string{"198.51.100.7"}
	v, err := e.svc.GetSettings(ctx, e.admin)
	if err != nil || len(v.Report) != 2 || !v.Report[0].OK || v.Report[1].OK || v.Report[1].Problem == "" {
		t.Fatalf("report = %+v, %v", v.Report, err)
	}

	bad := map[string]zones.Settings{
		"ipv4":        {IPv4: "2001:db8::1", TTL: 3600},
		"ipv6":        {IPv6: "192.0.2.1", TTL: 3600},
		"ttl":         {TTL: 1},
		"nameservers": {Nameservers: []string{"not a host"}, TTL: 3600},
		"template":    {TTL: 3600, Template: []zones.TemplateRecord{{Name: "@", Type: "CNAME", Content: "other.net"}}},
	}
	for name, s := range bad {
		var ve *validate.Error
		if _, _, err := e.svc.SaveSettings(ctx, client, e.admin, s); !errors.As(err, &ve) || ve.Field != name {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	set := v.Settings
	set.Nameservers = []string{"NS1.New.Example", "ns2.new.example", "ns1.new.example"}
	saved, queued, err := e.svc.SaveSettings(ctx, client, e.admin, set)
	if err != nil || queued != 1 || !slices.Equal(saved.Nameservers, []string{"ns1.new.example", "ns2.new.example"}) {
		t.Fatalf("save = %+v, %d, %v", saved, queued, err)
	}
	waitFor(t, func() bool { z, _ := e.fake.Zone("example.com"); return slices.Equal(z.Nameservers, saved.Nameservers) })

	// A new server address: the records pointing to the old one follow.
	set.IPv4 = "198.51.100.20"
	if _, _, err := e.svc.SaveSettings(ctx, client, e.admin, set); err != nil {
		t.Fatal(err)
	}
	e.waitServed(t, "example.com", has("@ A 198.51.100.20", "mail A 198.51.100.20", "@ AAAA 2001:db8::10"))
	e.waitServed(t, "example.com", lacks("@ A 192.0.2.10"))

	// No name servers set: each zone uses its own ns1 and ns2.
	set.Nameservers = nil
	if _, _, err := e.svc.SaveSettings(ctx, client, e.admin, set); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		z, _ := e.fake.Zone("example.com")
		return slices.Equal(z.Nameservers, []string{"ns1.example.com", "ns2.example.com"})
	})
}

func TestEnsureDomainsGivesOldDomainsDNS(t *testing.T) {
	e := newEnv(t)
	a, _ := e.account(t, "alice", "example.com")
	primary := e.mustDomains(t, a.ID)[0]
	e.add(t, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "blog", ParentID: primary.ID})
	waitFor(t, func() bool { return slices.Contains(e.served("example.com"), "blog A 192.0.2.10") })
	// As before DNS existed: no zones at all.
	if _, err := e.db.W.ExecContext(ctx, `DELETE FROM dns_zones`); err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.EnsureDomains(ctx)
	if err != nil || n != 2 {
		t.Fatalf("EnsureDomains = %d, %v", n, err)
	}
	if n, _ := e.svc.EnsureDomains(ctx); n != 0 {
		t.Fatalf("second run set up %d domains again", n)
	}
	zs, _ := e.db.AllZones(ctx)
	if len(zs) != 1 {
		t.Fatalf("zones = %+v", zs)
	}
	recs, _ := store.ZoneRecords(ctx, e.db.R, zs[0].ID)
	if !slices.ContainsFunc(recs, func(r store.ZoneRecord) bool { return r.Name == "blog.example.com" && r.Type == "A" }) {
		t.Fatalf("subdomain records missing: %+v", recs)
	}
	var _ agent.Zone // the fake agent's zones are agent.Zone values
}

func (e *env) runJob(t *testing.T, kind string) *jobs.Job {
	t.Helper()
	id, err := e.q.Enqueue(ctx, kind, struct{}{}, jobs.EnqueueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var j *jobs.Job
	waitFor(t, func() bool {
		j, _ = e.q.Get(ctx, id)
		return j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed
	})
	return j
}

func TestSyncAppliesZonesTheServerLacks(t *testing.T) {
	e := newEnv(t)
	e.account(t, "alice", "example.com")
	waitFor(t, func() bool { zs, _ := e.db.AllZones(ctx); return len(zs) == 1 && zs[0].Serving })
	// As if PowerDNS had not been there when the zone was made.
	if _, err := e.db.W.ExecContext(ctx, `UPDATE dns_zones SET serving = 0`); err != nil {
		t.Fatal(err)
	}
	e.fake.DNSZoneDelete(ctx, &agentv1.DNSZoneDeleteRequest{Zone: "example.com"})
	action := func(a agentv1.ServiceActionKind) {
		if _, err := e.fake.ServiceAction(ctx, &agentv1.ServiceActionRequest{Service: "dns", Action: a}); err != nil {
			t.Fatal(err)
		}
	}

	action(agentv1.ServiceActionKind_SERVICE_ACTION_KIND_STOP)
	if j := e.runJob(t, zones.JobSync); j.Status != jobs.StatusSucceeded || !strings.Contains(string(j.Result), "not running") {
		t.Fatalf("sync with the DNS server stopped: %s %s", j.Status, j.Result)
	}
	if _, ok := e.fake.Zone("example.com"); ok {
		t.Fatal("zone applied while the DNS server is stopped")
	}

	action(agentv1.ServiceActionKind_SERVICE_ACTION_KIND_START)
	if j := e.runJob(t, zones.JobSync); !strings.Contains(string(j.Result), `"queued":1`) {
		t.Fatalf("sync = %s", j.Result)
	}
	waitFor(t, func() bool { _, ok := e.fake.Zone("example.com"); return ok })
	waitFor(t, func() bool { zs, _ := e.db.AllZones(ctx); return zs[0].Serving })
	if j := e.runJob(t, zones.JobSync); !strings.Contains(string(j.Result), `"queued":0`) {
		t.Fatalf("nothing left to sync, got %s", j.Result)
	}
}
