package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// seedAccount adds a feature list, a package and an account through q.
func seedAccount(t *testing.T, q querier, id, username, domain string) {
	t.Helper()
	ctx := context.Background()
	if err := SaveFeatureList(ctx, q, &FeatureList{ID: "F" + id, Name: "f" + id}, true); err != nil {
		t.Fatal(err)
	}
	if err := SavePackage(ctx, q, &Package{ID: "P" + id, Name: "p" + id, FeatureListID: "F" + id, Limits: []byte("{}")}, true); err != nil {
		t.Fatal(err)
	}
	a := &Account{ID: id, Username: username, UID: 10000 + len(id), PackageID: "P" + id, PrimaryDomain: domain, Status: AccountActive}
	if err := InsertAccount(ctx, q, a); err != nil {
		t.Fatal(err)
	}
}

func TestDomainsMigrationAddsPrimaryDomains(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "xcp.db")
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ms, _ := loadMigrations()
	if err := runMigrations(ctx, w, path, ms[:5]); err != nil { // up to 0005, before domains existed
		t.Fatal(err)
	}
	seedAccount(t, w, "A1", "alice", "alice.example")
	if err := runMigrations(ctx, w, path, ms); err != nil {
		t.Fatal(err)
	}
	ds, err := queryDomains(ctx, w, `SELECT `+domainColumns+` FROM domains`)
	if err != nil || len(ds) != 1 {
		t.Fatalf("domains = %+v, %v", ds, err)
	}
	d := ds[0]
	if d.AccountID != "A1" || d.Name != "alice.example" || d.Kind != DomainPrimary || d.DocRoot != "public_html" || d.ID == "" {
		t.Fatalf("backfilled domain = %+v", d)
	}
}

func TestDomainsAndRedirects(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	seedAccount(t, db.W, "A1", "alice", "alice.example")
	seedAccount(t, db.W, "B22", "bob", "bob.example")
	add := func(id, account, name, kind, parent string) error {
		return InsertDomain(ctx, db.W, &Domain{ID: id, AccountID: account, Name: name, Kind: kind, ParentID: parent, DocRoot: "public_html"})
	}
	for _, d := range [][5]string{
		{"d1", "A1", "alice.example", DomainPrimary, ""},
		{"d2", "A1", "shop.alice.example", DomainSub, "d1"},
		{"d3", "A1", "*.alice.example", DomainSub, "d1"},
		{"d4", "B22", "bob.example", DomainPrimary, ""},
		{"d5", "B22", "alice-example.org", DomainAddon, ""}, // must not match "alice.example" below
	} {
		if err := add(d[0], d[1], d[2], d[3], d[4]); err != nil {
			t.Fatalf("%s: %v", d[2], err)
		}
	}
	if err := add("d6", "B22", "shop.alice.example", DomainAddon, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := add("d7", "A1", "second.example", DomainPrimary, ""); err == nil {
		t.Fatal("a second primary domain was accepted")
	}

	under, err := DomainsUnder(ctx, db.R, "alice.example")
	if err != nil || len(under) != 3 {
		t.Fatalf("DomainsUnder = %+v, %v", under, err)
	}
	if n, _ := CountDomains(ctx, db.R, "A1", DomainSub); n != 2 {
		t.Fatalf("subdomains = %d", n)
	}
	if n, _ := DomainDependents(ctx, db.R, "d1"); n != 2 {
		t.Fatalf("dependents = %d", n)
	}
	list, _ := db.ListDomains(ctx, "A1")
	if len(list) != 3 || list[0].Kind != DomainPrimary || list[1].Name != "*.alice.example" {
		t.Fatalf("list = %+v", list)
	}

	r := &Redirect{ID: "r1", DomainID: "d2", Path: "/old", Target: "https://alice.example/new", Code: 301, KeepPath: true}
	if err := InsertRedirect(ctx, db.W, r); err != nil {
		t.Fatal(err)
	}
	if err := InsertRedirect(ctx, db.W, &Redirect{ID: "r2", DomainID: "d2", Path: "/old", Target: "https://x.example/", Code: 302}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate path: %v", err)
	}
	got, err := db.RedirectByID(ctx, "r1")
	if err != nil || !got.KeepPath || got.Code != 301 || got.Path != "/old" {
		t.Fatalf("redirect = %+v, %v", got, err)
	}
	if rs, _ := db.ListRedirects(ctx, "A1"); len(rs) != 1 {
		t.Fatalf("redirects = %+v", rs)
	}

	if err := DeleteDomain(ctx, db.W, "d3"); err != nil {
		t.Fatal(err)
	}
	// Removing the account removes its domains (subdomains still pointing at
	// their parent included) and their redirects.
	if err := DeleteAccount(ctx, db.W, "A1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.ListDomains(ctx, "A1"); len(list) != 0 {
		t.Fatalf("domains left after the account: %+v", list)
	}
	if _, err := db.RedirectByID(ctx, "r1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("redirect left after its domain: %v", err)
	}
}
