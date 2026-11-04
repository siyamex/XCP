package accounts

import (
	"errors"
	"testing"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

func (e *env) reseller(t *testing.T, name string, lim store.ResellerLimits) *auth.Principal {
	t.Helper()
	l, err := e.auth.CreateLogin(ctx, client, e.admin, auth.NewLogin{Username: name, Password: pw, Role: store.RoleReseller, OwnerID: e.admin.Login.ID})
	if err != nil {
		t.Fatal(err)
	}
	lim.LoginID = l.ID
	if err := store.SetResellerLimits(ctx, e.db.W, lim, e.admin.Session.CreatedAt); err != nil {
		t.Fatal(err)
	}
	return &auth.Principal{Login: l, Session: &store.Session{}}
}

func i64(n int64) *int64 { return &n }

func (e *env) resellerPackage(t *testing.T, p *auth.Principal, name string, disk *int64) string {
	t.Helper()
	lists, err := e.plans.ListFeatureLists(ctx, p)
	if err != nil || len(lists) == 0 {
		t.Fatalf("a reseller sees the admin's feature lists: %v %v", lists, err)
	}
	pk, err := e.plans.SavePackage(ctx, client, p, "", plans.PackageInput{Name: name, FeatureListID: lists[0].ID, Limits: plans.Limits{DiskMB: disk}})
	if err != nil {
		t.Fatal(err)
	}
	return pk.ID
}

func TestResellerOwnsItsAccountsAndPackages(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller(t, "reseller1", store.ResellerLimits{})
	r2 := e.reseller(t, "reseller2", store.ResellerLimits{})

	// A reseller cannot use the admin's packages, nor change feature lists.
	if _, err := e.svc.Create(ctx, client, r1, CreateInput{Username: "cust1", Domain: "cust1.example", PackageID: e.pkgID, Password: pw}); err == nil {
		t.Error("a reseller used the admin's package")
	}
	if _, err := e.plans.SaveFeatureList(ctx, client, r1, "", plans.FeatureListInput{Name: "mine", Features: []string{"domains"}}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a reseller made a feature list: %v", err)
	}
	pk1 := e.resellerPackage(t, r1, "Small", i64(100))
	if got, _ := e.plans.ListPackages(ctx, r1); len(got) != 1 || got[0].ID != pk1 {
		t.Errorf("reseller1 packages: %+v", got)
	}
	if got, _ := e.plans.ListPackages(ctx, r2); len(got) != 0 {
		t.Errorf("reseller2 sees reseller1's packages: %+v", got)
	}
	if _, err := e.plans.GetPackage(ctx, r2, pk1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reseller2 reads the package: %v", err)
	}

	a, err := e.svc.Create(ctx, client, r1, CreateInput{Username: "cust1", Domain: "cust1.example", PackageID: pk1, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	if a.OwnerID != r1.Login.ID {
		t.Errorf("owner %q", a.OwnerID)
	}
	if j := e.waitJob(t, a.JobID); j.Status != "succeeded" {
		t.Fatalf("job %s: %s %v", j.Kind, j.Status, string(j.Result))
	}
	e.waitStatus(t, a.ID, store.AccountActive)

	if l, _ := e.svc.List(ctx, r1, "", ""); len(l) != 1 {
		t.Errorf("reseller1 lists %d", len(l))
	}
	if l, _ := e.svc.List(ctx, r2, "", ""); len(l) != 0 {
		t.Errorf("reseller2 lists %d", len(l))
	}
	if _, err := e.svc.Get(ctx, r2, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reseller2 reads reseller1's account: %v", err)
	}
	if _, err := e.svc.Suspend(ctx, client, r2, a.ID, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reseller2 suspends it: %v", err)
	}
	// Admins see every account, and which reseller owns it.
	all, _ := e.svc.List(ctx, e.admin, "", "")
	if len(all) != 1 || all[0].OwnerID != r1.Login.ID {
		t.Errorf("admin list: %+v", all)
	}
	// The reseller manages its customer.
	if _, err := e.svc.Suspend(ctx, client, r1, a.ID, "overdue"); err != nil {
		t.Fatal(err)
	}
	// A user cannot use the reseller functions.
	if _, err := e.svc.List(ctx, &auth.Principal{Login: &store.Login{Role: store.RoleUser}, Session: &store.Session{}}, "", ""); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user lists accounts: %v", err)
	}
}

func TestResellerQuota(t *testing.T) {
	e := newEnv(t)
	r := e.reseller(t, "reseller1", store.ResellerLimits{MaxAccounts: i64(2), DiskMB: i64(250)})
	small := e.resellerPackage(t, r, "Small", i64(100))
	big := e.resellerPackage(t, r, "Big", i64(200))
	unlimited := e.resellerPackage(t, r, "Unlimited", nil)
	mk := func(name, pkg string) error {
		_, err := e.svc.Create(ctx, client, r, CreateInput{Username: name, Domain: name + ".example", PackageID: pkg, Password: pw})
		return err
	}
	if err := mk("cust1", small); err != nil {
		t.Fatal(err)
	}
	var ce *apperr.Conflict
	if err := mk("cust2", unlimited); !errors.As(err, &ce) {
		t.Errorf("a package without a disk limit under a disk cap: %v", err)
	}
	if err := mk("cust2", big); !errors.As(err, &ce) {
		t.Errorf("100 + 200 MB over a 250 MB cap: %v", err)
	}
	if err := mk("cust2", small); err != nil {
		t.Fatal(err)
	}
	if err := mk("cust3", small); !errors.As(err, &ce) {
		t.Errorf("a third account over the limit of 2: %v", err)
	}

	// Overselling lifts the disk cap but not the number of accounts.
	if err := store.SetResellerLimits(ctx, e.db.W, store.ResellerLimits{LoginID: r.Login.ID, MaxAccounts: i64(3), DiskMB: i64(250), OversellDisk: true}, e.admin.Session.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := mk("cust3", unlimited); err != nil {
		t.Errorf("overselling: %v", err)
	}
	if err := mk("cust4", small); !errors.As(err, &ce) {
		t.Errorf("a fourth account over the limit of 3: %v", err)
	}
}
