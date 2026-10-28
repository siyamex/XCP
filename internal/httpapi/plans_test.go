package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

func TestPlansRequireAdmin(t *testing.T) {
	h := newHarness(t)
	if _, err := h.auth.CreateLogin(context.Background(), auth.Client{}, nil, auth.NewLogin{Username: "alice", Password: rootPW, Role: store.RoleUser}); err != nil {
		t.Fatal(err)
	}
	b := h.browser()
	b.login("alice", rootPW)
	for _, path := range []string{"/packages", "/feature-lists", "/features"} {
		wantProblem(t, b.do("GET", path, nil), 403, "forbidden")
	}
	wantProblem(t, b.do("POST", "/packages", map[string]any{"name": "x"}), 403, "forbidden")
}

func TestPackagesOverHTTP(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.login("root", rootPW)

	var feats struct{ Items []plans.Feature }
	json.NewDecoder(b.do("GET", "/features", nil).Body).Decode(&feats)
	if len(feats.Items) != len(plans.Catalog) {
		t.Fatalf("features = %d", len(feats.Items))
	}
	var pkgs struct{ Items []plans.Package }
	json.NewDecoder(b.do("GET", "/packages", nil).Body).Decode(&pkgs)
	if len(pkgs.Items) != 1 || pkgs.Items[0].Name != "Default" {
		t.Fatalf("default package missing: %+v", pkgs.Items)
	}

	resp := b.do("POST", "/feature-lists", map[string]any{"name": "Email only", "features": []string{"email", "webmail"}})
	var fl plans.FeatureList
	json.NewDecoder(resp.Body).Decode(&fl)
	if resp.StatusCode != 201 || fl.ID == "" {
		t.Fatalf("create list = %d %+v", resp.StatusCode, fl)
	}

	resp = b.do("POST", "/packages", map[string]any{
		"name": "Mail", "feature_list_id": fl.ID,
		"limits": map[string]any{"disk_mb": 2048, "mailboxes": 10, "databases": nil},
	})
	var p plans.Package
	json.NewDecoder(resp.Body).Decode(&p)
	if resp.StatusCode != 201 || *p.Limits.DiskMB != 2048 || p.Limits.Databases != nil {
		t.Fatalf("create package = %d %+v", resp.StatusCode, p)
	}

	wantProblem(t, b.do("POST", "/packages", map[string]any{"name": "Mail", "feature_list_id": fl.ID, "limits": map[string]any{}}), 409, "name_taken")
	wantProblem(t, b.do("POST", "/packages", map[string]any{"name": "X", "feature_list_id": fl.ID, "limits": map[string]any{"disk": 1}}), 400, "bad_json")
	pr := wantProblem(t, b.do("POST", "/packages", map[string]any{"name": "X", "feature_list_id": fl.ID, "limits": map[string]any{"shell": "zsh"}}), 400, "validation_failed")
	if pr.Errors[0].Field != "limits.shell" {
		t.Fatalf("field = %+v", pr.Errors)
	}

	resp = b.do("PUT", "/packages/"+p.ID, map[string]any{"name": "Mail Plus", "feature_list_id": fl.ID, "limits": map[string]any{"disk_mb": 4096}})
	json.NewDecoder(resp.Body).Decode(&p)
	if resp.StatusCode != 200 || p.Name != "Mail Plus" || *p.Limits.DiskMB != 4096 || p.Limits.Mailboxes != nil {
		t.Fatalf("update = %d %+v", resp.StatusCode, p)
	}
	wantProblem(t, b.do("DELETE", "/feature-lists/"+fl.ID, nil), 409, "in_use")
	if resp := b.do("DELETE", "/packages/"+p.ID, nil); resp.StatusCode != 204 {
		t.Fatalf("delete package = %d", resp.StatusCode)
	}
	if resp := b.do("DELETE", "/feature-lists/"+fl.ID, nil); resp.StatusCode != 204 {
		t.Fatalf("delete list = %d", resp.StatusCode)
	}
	wantProblem(t, b.do("GET", "/packages/"+p.ID, nil), 404, "not_found")
}
