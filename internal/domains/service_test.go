package domains_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
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
	svc   *domains.Service
	accts *accounts.Service
	plans *plans.Service
	db    *store.DB
	q     *jobs.Queue
	fake  *agentrpc.Fake
	txt   domains.StaticTXT
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
	txt := domains.StaticTXT{}
	zs := zones.NewService(db, rec, pl, q, fake, zones.StaticHosts{})
	svc := domains.NewService(db, rec, pl, q, fake, zs, txt, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, svc, zs)
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	accts.RegisterJobs(w)
	svc.RegisterJobs(w)
	zs.RegisterJobs(w)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, accts: accts, plans: pl, db: db, q: q, fake: fake, txt: txt, admin: admin, pkgID: pkgs[0].ID}
}

// account creates an active account and returns it with its user login.
func (e *env) account(t *testing.T, user, domain string) (accounts.Account, *auth.Principal) {
	t.Helper()
	a, err := e.accts.Create(ctx, client, e.admin, accounts.CreateInput{Username: user, Domain: domain, PackageID: e.pkgID, Password: pw})
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

func (e *env) waitJob(t *testing.T, id string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, err := e.q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			if j.Status == jobs.StatusFailed {
				t.Fatalf("job %s (%s) failed: %s", id, j.Kind, j.Error)
			}
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// vhosts returns the fake agent's virtual hosts of an account by name.
func (e *env) vhosts(t *testing.T, user string) map[string]agent.Vhost {
	t.Helper()
	site, ok := e.fake.Site(user)
	if !ok {
		t.Fatalf("no site for %s", user)
	}
	m := map[string]agent.Vhost{}
	for _, v := range site.Vhosts {
		m[v.Name] = v
	}
	return m
}

func conflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func field(err error, name string) bool {
	var ve *validate.Error
	return errors.As(err, &ve) && ve.Field == name
}

func TestDomainLifecycle(t *testing.T) {
	e := newEnv(t)
	a, _ := e.account(t, "alice", "alice.example")
	list, err := e.svc.List(ctx, e.admin, a.ID)
	if err != nil || len(list) != 1 || list[0].Kind != store.DomainPrimary || list[0].DocRoot != "public_html" {
		t.Fatalf("new account's domains = %+v, %v", list, err)
	}
	primary := list[0]

	add := func(in domains.AddInput) domains.Domain {
		t.Helper()
		d, err := e.svc.Add(ctx, client, e.admin, a.ID, in)
		if err != nil {
			t.Fatalf("add %+v: %v", in, err)
		}
		e.waitJob(t, d.JobID)
		return d
	}
	shop := add(domains.AddInput{Kind: store.DomainAddon, Name: "WWW.Shop.Example"})
	if shop.Name != "shop.example" || shop.DocRoot != "domains/shop.example" {
		t.Fatalf("addon = %+v", shop)
	}
	blog := add(domains.AddInput{Kind: store.DomainSub, Name: "Blog", ParentID: primary.ID, DocRoot: "/public_html/blog/"})
	wild := add(domains.AddInput{Kind: store.DomainSub, Name: "*", ParentID: shop.ID})
	alias := add(domains.AddInput{Kind: store.DomainAlias, Name: "bücher.example", ParentID: shop.ID})
	if blog.Name != "blog.alice.example" || blog.DocRoot != "public_html/blog" || wild.Name != "*.shop.example" ||
		wild.DocRoot != "domains/_wildcard.shop.example" || alias.Name != "xn--bcher-kva.example" ||
		alias.DisplayName != "bücher.example" || alias.DocRoot != "domains/shop.example" || alias.ParentName != "shop.example" {
		t.Fatalf("sub %+v\nwildcard %+v\nalias %+v", blog, wild, alias)
	}

	// The agent gets one virtual host per domain; the alias shows the shop's site.
	vh := e.vhosts(t, "alice")
	if len(vh) != 5 || vh["xn--bcher-kva.example"].DocRoot != "domains/shop.example" || vh["blog.alice.example"].DocRoot != "public_html/blog" {
		t.Fatalf("vhosts = %+v", vh)
	}
	if site, _ := e.fake.Site("alice"); site.Vhosts[0].Name != "alice.example" {
		t.Fatalf("primary domain must come first: %+v", site.Vhosts)
	}

	u, err := e.svc.Update(ctx, client, e.admin, shop.ID, domains.UpdateInput{DocRoot: "sites/shop", Canonical: store.CanonicalWWW})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, u.JobID)
	if v := e.vhosts(t, "alice"); v["shop.example"].DocRoot != "sites/shop" || v["shop.example"].Canonical != agent.CanonicalWWW ||
		v["xn--bcher-kva.example"].DocRoot != "sites/shop" {
		t.Fatalf("after update: %+v", v)
	}

	r, err := e.svc.AddRedirect(ctx, client, e.admin, shop.ID, domains.RedirectInput{Path: "/old/", Target: "https://shop.example/new", Code: 301, KeepPath: true})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, r.JobID)
	if rs := e.vhosts(t, "alice")["shop.example"].Redirects; len(rs) != 1 || rs[0] != (agent.Redirect{Path: "/old", Target: "https://shop.example/new", Code: 301, KeepPath: true}) {
		t.Fatalf("redirects = %+v", rs)
	}
	if _, err := e.svc.AddRedirect(ctx, client, e.admin, shop.ID, domains.RedirectInput{Path: "/old", Target: "https://x.example/", Code: 302}); !conflict(err, "redirect_exists") {
		t.Fatalf("duplicate redirect: %v", err)
	}

	if _, err := e.svc.Delete(ctx, client, e.admin, primary.ID); !conflict(err, "primary_domain") {
		t.Fatalf("delete primary: %v", err)
	}
	if _, err := e.svc.Delete(ctx, client, e.admin, shop.ID); !conflict(err, "has_dependents") {
		t.Fatalf("delete domain with an alias and a subdomain: %v", err)
	}
	for _, d := range []domains.Domain{alias, wild, shop} {
		jobID, err := e.svc.Delete(ctx, client, e.admin, d.ID)
		if err != nil {
			t.Fatalf("delete %s: %v", d.Name, err)
		}
		e.waitJob(t, jobID)
	}
	if v := e.vhosts(t, "alice"); len(v) != 2 {
		t.Fatalf("after deletes: %+v", v)
	}
	if rs, _ := e.svc.ListRedirects(ctx, e.admin, a.ID); len(rs) != 0 {
		t.Fatalf("redirects of a removed domain remain: %+v", rs)
	}
	// The name is free again, also for another account.
	b, _ := e.account(t, "bob", "bob.example")
	if _, err := e.svc.Add(ctx, client, e.admin, b.ID, domains.AddInput{Kind: store.DomainAddon, Name: "shop.example"}); err != nil {
		t.Fatalf("re-add a removed name elsewhere: %v", err)
	}
	if _, err := e.svc.Add(ctx, client, e.admin, b.ID, domains.AddInput{Kind: store.DomainAlias, Name: "blog.alice.example", ParentID: firstID(t, e, b.ID)}); !conflict(err, "domain_taken") {
		t.Fatalf("take another account's domain: %v", err)
	}
}

func firstID(t *testing.T, e *env, accountID string) string {
	t.Helper()
	list, err := e.svc.List(ctx, e.admin, accountID)
	if err != nil {
		t.Fatal(err)
	}
	return list[0].ID
}

func TestAddValidation(t *testing.T) {
	e := newEnv(t)
	a, _ := e.account(t, "alice", "alice.example")
	primary := firstID(t, e, a.ID)
	alias, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAlias, Name: "other.example", ParentID: primary})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		in    domains.AddInput
		field string
	}{
		"bad kind":         {domains.AddInput{Kind: "primary", Name: "x.example"}, "kind"},
		"bad name":         {domains.AddInput{Kind: store.DomainAddon, Name: "not a domain"}, "name"},
		"public suffix":    {domains.AddInput{Kind: store.DomainAddon, Name: "co.uk"}, "name"},
		"www sub":          {domains.AddInput{Kind: store.DomainSub, Name: "www", ParentID: primary}, "name"},
		"sub of an alias":  {domains.AddInput{Kind: store.DomainSub, Name: "x", ParentID: alias.ID}, "parent_id"},
		"no parent":        {domains.AddInput{Kind: store.DomainAlias, Name: "y.example"}, "parent_id"},
		"tmp docroot":      {domains.AddInput{Kind: store.DomainAddon, Name: "z.example", DocRoot: "tmp"}, "docroot"},
		"escaping docroot": {domains.AddInput{Kind: store.DomainAddon, Name: "z.example", DocRoot: "../bob"}, "docroot"},
	}
	for name, c := range cases {
		if _, err := e.svc.Add(ctx, client, e.admin, a.ID, c.in); !field(err, c.field) {
			t.Errorf("%s: err = %v, want a %s field error", name, err, c.field)
		}
	}
	if _, err := e.svc.Update(ctx, client, e.admin, alias.ID, domains.UpdateInput{DocRoot: "x"}); !field(err, "docroot") {
		t.Errorf("alias with its own docroot: %v", err)
	}
	for _, in := range []domains.RedirectInput{
		{Path: "/", Target: "https://x.example/$1", Code: 301},
		{Path: "/", Target: "https://x.example/?a=1", Code: 301, KeepPath: true},
		{Path: "/a b", Target: "https://x.example/", Code: 301},
		{Path: "/", Target: "https://x.example/", Code: 200},
	} {
		if _, err := e.svc.AddRedirect(ctx, client, e.admin, primary, in); !errors.Is(err, validate.ErrValidation) {
			t.Errorf("redirect %+v: err = %v", in, err)
		}
	}
}

func TestPackageLimits(t *testing.T) {
	e := newEnv(t)
	one := int64(1)
	lim := plans.DefaultLimits()
	lim.AddonDomains, lim.Subdomains = &one, &one
	pkgs, _ := e.plans.ListPackages(ctx, e.admin)
	small, err := e.plans.SavePackage(ctx, client, e.admin, "", plans.PackageInput{Name: "Small", FeatureListID: pkgs[0].FeatureListID, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	e.pkgID = small.ID
	a, _ := e.account(t, "alice", "alice.example")
	primary := firstID(t, e, a.ID)
	if _, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "one.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "two.example"}); !conflict(err, "limit_reached") {
		t.Fatalf("second addon: %v", err)
	}
	if _, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "a", ParentID: primary}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "b", ParentID: primary}); !conflict(err, "limit_reached") {
		t.Fatalf("second subdomain: %v", err)
	}
	// Aliases are limited separately (10 in the default limits).
	if _, err := e.svc.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAlias, Name: "alias.example", ParentID: primary}); err != nil {
		t.Fatal(err)
	}
}

func TestUserReachesOnlyOwnAccountWithTheFeature(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice", "alice.example")
	b, _ := e.account(t, "bob", "bob.example")
	if list, err := e.svc.List(ctx, alice, a.ID); err != nil || len(list) != 1 {
		t.Fatalf("own domains: %+v, %v", list, err)
	}
	d, err := e.svc.Add(ctx, client, alice, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "alice-shop.example"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, d.JobID)
	if _, err := e.svc.List(ctx, alice, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other account's domains: %v", err)
	}
	if _, err := e.svc.Delete(ctx, client, alice, firstID(t, e, b.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete other account's domain: %v", err)
	}

	// A package whose feature list lacks "redirects" (and later "domains").
	fl, err := e.plans.SaveFeatureList(ctx, client, e.admin, "", plans.FeatureListInput{Name: "No redirects", Features: []string{"domains"}})
	if err != nil {
		t.Fatal(err)
	}
	pk, err := e.plans.SavePackage(ctx, client, e.admin, "", plans.PackageInput{Name: "Basic", FeatureListID: fl.ID, Limits: plans.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	up, err := e.accts.Update(ctx, client, e.admin, a.ID, accounts.UpdateInput{PackageID: pk.ID})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, up.JobID)
	if _, err := e.svc.AddRedirect(ctx, client, alice, d.ID, domains.RedirectInput{Path: "/", Target: "https://x.example/", Code: 301}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("redirect without the feature: %v", err)
	}
	if _, err := e.svc.AddRedirect(ctx, client, e.admin, d.ID, domains.RedirectInput{Path: "/", Target: "https://x.example/", Code: 301}); err != nil {
		t.Fatalf("admins are not bound by the feature list: %v", err)
	}
	if _, err := e.plans.SaveFeatureList(ctx, client, e.admin, fl.ID, plans.FeatureListInput{Name: "Nothing", Features: []string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.List(ctx, alice, a.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("domains without the feature: %v", err)
	}
}

func TestVerificationStopsTakeover(t *testing.T) {
	e := newEnv(t)
	_, alice := e.account(t, "alice", "example.com")
	b, bob := e.account(t, "bob", "bob.example")

	// Alice may add names below her own domain freely.
	if _, err := e.svc.Add(ctx, client, alice, alice.Login.AccountID, domains.AddInput{Kind: store.DomainAddon, Name: "deep.blog.example.com"}); err != nil {
		t.Fatalf("own subtree: %v", err)
	}
	// Bob may not claim a name under Alice's registered domain without proof.
	in := domains.AddInput{Kind: store.DomainAddon, Name: "shop.example.com"}
	if _, err := e.svc.Add(ctx, client, bob, b.ID, in); !conflict(err, "verification_required") {
		t.Fatalf("takeover attempt: %v", err)
	}
	v, err := e.svc.Verification(ctx, bob, b.ID, "shop.example.com")
	if err != nil || !v.Required || v.Verified || v.Record != "_xcp-verify.shop.example.com" || len(v.Value) < 20 {
		t.Fatalf("verification = %+v, %v", v, err)
	}
	if other, _ := e.svc.Verification(ctx, alice, alice.Login.AccountID, "shop.example.com"); other.Required || other.Value == v.Value {
		t.Fatalf("token must be per account, and Alice needs none: %+v", other)
	}
	e.txt[v.Record] = []string{"unrelated", v.Value}
	if v, _ := e.svc.Verification(ctx, bob, b.ID, "shop.example.com"); !v.Verified {
		t.Fatal("published record not seen")
	}
	if _, err := e.svc.Add(ctx, client, bob, b.ID, in); err != nil {
		t.Fatalf("verified add: %v", err)
	}
	// The verified name gives Bob no claim on the rest of example.com.
	if _, err := e.svc.Add(ctx, client, bob, b.ID, domains.AddInput{Kind: store.DomainAddon, Name: "mail.example.com"}); !conflict(err, "verification_required") {
		t.Fatalf("sibling name: %v", err)
	}
	// An unused registered domain needs no proof; admins never do.
	if _, err := e.svc.Add(ctx, client, bob, b.ID, domains.AddInput{Kind: store.DomainAddon, Name: "fresh.example.net"}); err != nil {
		t.Fatalf("unused domain: %v", err)
	}
	if _, err := e.svc.Add(ctx, client, e.admin, b.ID, domains.AddInput{Kind: store.DomainAddon, Name: "admin.example.com"}); err != nil {
		t.Fatalf("admin: %v", err)
	}
	list, _ := e.svc.List(ctx, bob, b.ID)
	names := make([]string, len(list))
	for i, d := range list {
		names[i] = d.Name
	}
	if !slices.Contains(names, "shop.example.com") || !slices.Contains(names, "admin.example.com") {
		t.Fatalf("bob's domains = %v", names)
	}
}
