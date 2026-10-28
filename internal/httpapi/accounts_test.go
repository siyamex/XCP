package httpapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/plans"
)

func (b *browser) waitJob(t *testing.T, id string) jobJSON {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var j jobJSON
		json.NewDecoder(b.do("GET", "/jobs/"+id, nil).Body).Decode(&j)
		if j.Status == "succeeded" || j.Status == "failed" {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s: %+v", id, j)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAccountsOverHTTP(t *testing.T) {
	h := newHarness(t)
	admin := h.browser()
	admin.login("root", rootPW)
	var pkgs struct{ Items []plans.Package }
	json.NewDecoder(admin.do("GET", "/packages", nil).Body).Decode(&pkgs)

	resp := admin.do("POST", "/accounts", map[string]any{
		"username": "alice", "domain": "alice.example",
		"package_id": pkgs.Items[0].ID, "password": rootPW, "email": "alice@example.org",
	})
	var a accounts.Account
	json.NewDecoder(resp.Body).Decode(&a)
	if resp.StatusCode != 202 || a.Status != "creating" || a.JobID == "" {
		t.Fatalf("create = %d %+v", resp.StatusCode, a)
	}
	if j := admin.waitJob(t, a.JobID); j.Status != "succeeded" || j.Kind != "account.apply" {
		t.Fatalf("job = %+v", j)
	}
	json.NewDecoder(admin.do("GET", "/accounts/"+a.ID, nil).Body).Decode(&a)
	if a.Status != "active" || a.UID != 10000 || a.PackageName != "Default" {
		t.Fatalf("after job: %+v", a)
	}
	var list struct{ Items []accounts.Account }
	json.NewDecoder(admin.do("GET", "/accounts?search=ALI", nil).Body).Decode(&list)
	if len(list.Items) != 1 {
		t.Fatalf("search = %+v", list.Items)
	}

	wantProblem(t, admin.do("POST", "/accounts", map[string]any{
		"username": "alice", "domain": "other.example",
		"package_id": pkgs.Items[0].ID, "password": rootPW,
	}), 409, "username_taken")

	// The account's own login is a "user": admin endpoints are closed to it,
	// but it may follow its own account's jobs.
	user := h.browser()
	user.login("alice", rootPW)
	wantProblem(t, user.do("GET", "/accounts", nil), 403, "forbidden")
	if j := user.waitJob(t, a.JobID); j.AccountID != a.ID {
		t.Fatalf("own job = %+v", j)
	}

	resp = admin.do("POST", "/accounts/"+a.ID+"/suspend", map[string]any{"reason": "abuse report"})
	if resp.StatusCode != 202 {
		t.Fatalf("suspend = %d %s", resp.StatusCode, readAll(resp))
	}
	wantProblem(t, user.do("GET", "/me", nil), 401, "unauthenticated")
	wantProblem(t, h.browser().do("POST", "/auth/login", map[string]string{"username": "alice", "password": rootPW}), 403, "login_disabled")
	wantProblem(t, admin.do("POST", "/accounts/"+a.ID+"/suspend", map[string]any{}), 409, "bad_status")

	pr := wantProblem(t, admin.do("POST", "/accounts/"+a.ID+"/terminate", map[string]any{"confirm": "bob"}), 400, "validation_failed")
	if pr.Errors[0].Field != "confirm" {
		t.Fatalf("errors = %+v", pr.Errors)
	}
	resp = admin.do("POST", "/accounts/"+a.ID+"/terminate", map[string]any{"confirm": "alice"})
	json.NewDecoder(resp.Body).Decode(&a)
	if resp.StatusCode != 202 || a.Status != "terminating" {
		t.Fatalf("terminate = %d %+v", resp.StatusCode, a)
	}
	if j := admin.waitJob(t, a.JobID); j.Status != "succeeded" {
		t.Fatalf("terminate job = %+v", j)
	}
	wantProblem(t, admin.do("GET", "/accounts/"+a.ID, nil), 404, "not_found")
}
