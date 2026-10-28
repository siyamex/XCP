package plans

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
	admin  = &auth.Principal{Login: &store.Login{ID: "A1", Role: store.RoleAdmin}, Session: &store.Session{}}
	user   = &auth.Principal{Login: &store.Login{ID: "U1", Role: store.RoleUser}, Session: &store.Session{}}
)

func newService(t *testing.T) (*Service, *audit.Recorder) {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rec := audit.NewRecorder(db)
	return NewService(db, rec), rec
}

func i64(v int64) *int64 { return &v }

func wantField(t *testing.T, err error, field string) {
	t.Helper()
	var ve *validate.Error
	if !errors.As(err, &ve) || ve.Field != field {
		t.Fatalf("err = %v, want validation error on %s", err, field)
	}
}

func wantConflict(t *testing.T, err error, code string) {
	t.Helper()
	var c *apperr.Conflict
	if !errors.As(err, &c) || c.Code != code {
		t.Fatalf("err = %v, want conflict %s", err, code)
	}
}

func TestEnsureDefaultsOnceAndSane(t *testing.T) {
	s, _ := newService(t)
	for range 2 {
		if err := s.EnsureDefaults(ctx); err != nil {
			t.Fatal(err)
		}
	}
	lists, _ := s.ListFeatureLists(ctx, admin)
	pkgs, _ := s.ListPackages(ctx, admin)
	if len(lists) != 1 || len(pkgs) != 1 || pkgs[0].FeatureListID != lists[0].ID {
		t.Fatalf("defaults: lists=%v pkgs=%v", lists, pkgs)
	}
	if slices.Contains(lists[0].Features, "ssh") || slices.Contains(lists[0].Features, "terminal") || !slices.Contains(lists[0].Features, "email") {
		t.Fatalf("default features = %v", lists[0].Features)
	}
	if l := pkgs[0].Limits; l.Shell != ShellNone || l.DiskMB == nil || *l.DiskMB != 10240 {
		t.Fatalf("default limits = %+v", l)
	}
}

func TestOnlyAdminsManagePlans(t *testing.T) {
	s, _ := newService(t)
	calls := map[string]error{}
	_, calls["list lists"] = s.ListFeatureLists(ctx, user)
	_, calls["list packages"] = s.ListPackages(ctx, user)
	_, calls["create list"] = s.SaveFeatureList(ctx, client, user, "", FeatureListInput{Name: "x"})
	_, calls["create package"] = s.SavePackage(ctx, client, user, "", PackageInput{Name: "x"})
	calls["delete package"] = s.DeletePackage(ctx, client, user, "any")
	_, calls["nil principal"] = s.ListPackages(ctx, nil)
	for name, err := range calls {
		if !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s: err = %v, want ErrForbidden", name, err)
		}
	}
}

func TestFeatureListValidationAndConflicts(t *testing.T) {
	s, _ := newService(t)
	_, err := s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "Basic", Features: []string{"email", "root_shell"}})
	wantField(t, err, "features")
	_, err = s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "  "})
	wantField(t, err, "name")
	_, err = s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "bad<script>"})
	wantField(t, err, "name")

	f, err := s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "  Basic   plan ", Features: []string{"ftp", "email", "email", "domains"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "Basic plan" || !slices.Equal(f.Features, []string{"domains", "email", "ftp"}) {
		t.Fatalf("saved = %+v (want trimmed name, catalog order, no duplicates)", f)
	}
	_, err = s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "Basic plan"})
	wantConflict(t, err, "name_taken")

	f2, err := s.SaveFeatureList(ctx, client, admin, f.ID, FeatureListInput{Name: "Basic", Features: []string{"ssh"}})
	if err != nil || f2.ID != f.ID || !slices.Equal(f2.Features, []string{"ssh"}) {
		t.Fatalf("update = %+v, %v", f2, err)
	}
	if _, err := s.SaveFeatureList(ctx, client, admin, "missing", FeatureListInput{Name: "X"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func TestPackageLifecycle(t *testing.T) {
	s, rec := newService(t)
	fl, _ := s.SaveFeatureList(ctx, client, admin, "", FeatureListInput{Name: "All", Features: AllFeatures()})

	bad := map[string]PackageInput{
		"limits.disk_mb":      {Name: "P", FeatureListID: fl.ID, Limits: Limits{DiskMB: i64(-1)}},
		"limits.shell":        {Name: "P", FeatureListID: fl.ID, Limits: Limits{Shell: "bash"}},
		"limits.php_versions": {Name: "P", FeatureListID: fl.ID, Limits: Limits{PHPVersions: []string{"8.3", "latest"}}},
		"limits.cpu_percent":  {Name: "P", FeatureListID: fl.ID, Limits: Limits{CPUPercent: i64(3)}},
		"feature_list_id":     {Name: "P", FeatureListID: "nope"},
	}
	for fieldName, in := range bad {
		_, err := s.SavePackage(ctx, client, admin, "", in)
		wantField(t, err, fieldName)
	}

	p, err := s.SavePackage(ctx, client, admin, "", PackageInput{Name: "Gold", FeatureListID: fl.ID,
		Limits: Limits{DiskMB: i64(50000), PHPVersions: []string{"8.3", "8.1", "8.3"}}})
	if err != nil {
		t.Fatal(err)
	}
	if *p.Limits.DiskMB != 50000 || p.Limits.Mailboxes != nil || p.Limits.Shell != ShellNone || !slices.Equal(p.Limits.PHPVersions, []string{"8.1", "8.3"}) {
		t.Fatalf("limits = %+v (nil must stay unlimited)", p.Limits)
	}
	raw, _ := json.Marshal(p.Limits)
	if !json.Valid(raw) || !slices.Contains([]string{`null`}, string(mustField(t, raw, "mailboxes"))) {
		t.Fatalf("unlimited must serialise as null: %s", raw)
	}

	_, err = s.SavePackage(ctx, client, admin, "", PackageInput{Name: "Gold", FeatureListID: fl.ID})
	wantConflict(t, err, "name_taken")

	if err := s.DeleteFeatureList(ctx, client, admin, fl.ID); err == nil {
		t.Fatal("deleted a feature list that a package uses")
	} else {
		wantConflict(t, err, "in_use")
	}
	if err := s.DeletePackage(ctx, client, admin, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPackage(ctx, admin, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	if err := s.DeleteFeatureList(ctx, client, admin, fl.ID); err != nil {
		t.Fatalf("delete unused list: %v", err)
	}
	// create list, create package, delete package, delete list
	if n, err := rec.Verify(ctx); err != nil || n != 4 {
		t.Fatalf("audit: %d entries, %v", n, err)
	}
}

func mustField(t *testing.T, raw []byte, key string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m[key]
}
