package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/plans"
)

func TestDomainsOverHTTP(t *testing.T) {
	h := newHarness(t)
	admin := h.browser()
	admin.login("root", rootPW)
	var pkgs struct{ Items []plans.Package }
	json.NewDecoder(admin.do("GET", "/packages", nil).Body).Decode(&pkgs)
	create := func(user, domain string) accounts.Account {
		var a accounts.Account
		json.NewDecoder(admin.do("POST", "/accounts", map[string]any{
			"username": user, "domain": domain, "package_id": pkgs.Items[0].ID, "password": rootPW,
		}).Body).Decode(&a)
		if j := admin.waitJob(t, a.JobID); j.Status != "succeeded" {
			t.Fatalf("create %s: %+v", user, j)
		}
		return a
	}
	alice, bob := create("alice", "alice.example"), create("bob", "bob.example")

	user := h.browser()
	user.login("alice", rootPW)
	var me meResponse
	json.NewDecoder(user.do("GET", "/me", nil).Body).Decode(&me)
	if me.AccountID != alice.ID {
		t.Fatalf("me.account_id = %q, want %q", me.AccountID, alice.ID)
	}

	resp := user.do("POST", "/accounts/"+alice.ID+"/domains", map[string]any{"kind": "addon", "name": "shop.example"})
	var d domains.Domain
	json.NewDecoder(resp.Body).Decode(&d)
	if resp.StatusCode != 202 || d.Name != "shop.example" || d.JobID == "" {
		t.Fatalf("add = %d %+v", resp.StatusCode, d)
	}
	if j := user.waitJob(t, d.JobID); j.Status != "succeeded" || j.Kind != domains.JobSiteApply {
		t.Fatalf("job = %+v", j)
	}
	var list struct{ Items []domains.Domain }
	json.NewDecoder(user.do("GET", "/accounts/"+alice.ID+"/domains", nil).Body).Decode(&list)
	if len(list.Items) != 2 || list.Items[0].Kind != "primary" {
		t.Fatalf("list = %+v", list.Items)
	}
	wantProblem(t, user.do("POST", "/accounts/"+alice.ID+"/domains", map[string]any{"kind": "addon", "name": "shop.example"}), 409, "domain_taken")
	wantProblem(t, user.do("POST", "/accounts/"+alice.ID+"/domains", map[string]any{"kind": "addon", "name": "x.example", "extra": 1}), 400, "bad_json")

	// Nothing of Bob's is visible to Alice.
	wantProblem(t, user.do("GET", "/accounts/"+bob.ID+"/domains", nil), 404, "not_found")
	wantProblem(t, user.do("GET", "/jobs/"+bob.JobID, nil), 404, "not_found")
	wantProblem(t, user.do("GET", "/accounts", nil), 403, "forbidden")

	var v domains.Verification
	json.NewDecoder(user.do("GET", "/accounts/"+alice.ID+"/domain-verification?name=new.example", nil).Body).Decode(&v)
	if v.Name != "new.example" || v.Required {
		t.Fatalf("verification = %+v", v)
	}

	resp = user.do("POST", "/domains/"+d.ID+"/redirects", map[string]any{"path": "/old", "target": "https://shop.example/new", "code": 301})
	var r domains.Redirect
	json.NewDecoder(resp.Body).Decode(&r)
	if resp.StatusCode != 202 || r.Domain != "shop.example" {
		t.Fatalf("add redirect = %d %+v", resp.StatusCode, r)
	}
	user.waitJob(t, r.JobID)
	var rs struct{ Items []domains.Redirect }
	json.NewDecoder(admin.do("GET", "/accounts/"+alice.ID+"/redirects", nil).Body).Decode(&rs)
	if len(rs.Items) != 1 {
		t.Fatalf("redirects = %+v", rs.Items)
	}
	var ref struct {
		JobID string `json:"job_id"`
	}
	resp = user.do("DELETE", "/redirects/"+r.ID, nil)
	json.NewDecoder(resp.Body).Decode(&ref)
	if resp.StatusCode != 202 || ref.JobID == "" {
		t.Fatalf("delete redirect = %d %+v", resp.StatusCode, ref)
	}
	resp = user.do("PUT", "/domains/"+d.ID, map[string]any{"docroot": "sites/shop", "canonical": "www"})
	json.NewDecoder(resp.Body).Decode(&d)
	if resp.StatusCode != 202 || d.DocRoot != "sites/shop" || d.Canonical != "www" {
		t.Fatalf("update = %d %+v", resp.StatusCode, d)
	}
	resp = user.do("DELETE", "/domains/"+d.ID, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("delete = %d %s", resp.StatusCode, readAll(resp))
	}
	wantProblem(t, user.do("DELETE", "/domains/"+list.Items[0].ID, nil), 409, "primary_domain")
}
