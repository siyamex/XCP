package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAPITokensOverHTTP(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.login("root", rootPW)

	resp := b.do("POST", "/me/tokens", map[string]any{"name": "ci", "scope": "read", "password": "wrong password!"})
	if resp.StatusCode == 201 {
		t.Fatal("a token was made with a wrong password")
	}
	resp = b.do("POST", "/me/tokens", map[string]any{"name": "ci", "scope": "read", "password": rootPW})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, readAll(resp))
	}
	var rd struct {
		ID, Secret string
	}
	var raw map[string]any
	json.Unmarshal([]byte(readAll(resp)), &raw)
	rd.ID, _ = raw["id"].(string)
	rd.Secret, _ = raw["secret"].(string)
	if !strings.HasPrefix(rd.Secret, "xcp_") {
		t.Fatalf("secret %q", rd.Secret)
	}

	// A script has no cookie and no CSRF token.
	script := h.browser()
	bearer := header("Authorization", "Bearer "+rd.Secret)
	if resp := script.do("GET", "/me", nil, bearer); resp.StatusCode != 200 {
		t.Fatalf("GET /me with a token: %d %s", resp.StatusCode, readAll(resp))
	}
	if resp := script.do("GET", "/packages", nil, bearer); resp.StatusCode != 200 {
		t.Fatalf("GET /packages with a token: %d %s", resp.StatusCode, readAll(resp))
	}
	// Read only.
	wantProblem(t, script.do("POST", "/packages", map[string]any{"name": "x"}, bearer), 403, "token_read_only")
	// Not the pages for a person.
	wantProblem(t, script.do("GET", "/me/tokens", nil, bearer), 403, "token_not_allowed")
	wantProblem(t, script.do("POST", "/me/password", map[string]any{"current_password": rootPW, "new_password": "another long password"}, bearer), 403, "token_read_only")
	// Wrong tokens are plain 401s.
	wantProblem(t, script.do("GET", "/me", nil, header("Authorization", "Bearer xcp_00000000_"+strings.Repeat("0", 48))), 401, "unauthenticated")
	wantProblem(t, script.do("GET", "/me", nil, header("Authorization", "Bearer nonsense")), 401, "unauthenticated")

	// Revoked, it stops working.
	if resp := b.do("DELETE", "/me/tokens/"+rd.ID, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	wantProblem(t, script.do("GET", "/me", nil, bearer), 401, "unauthenticated")
}

func TestImpersonationOverHTTP(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.login("root", rootPW)
	// An account to enter.
	var pk struct{ Items []struct{ ID string } }
	json.Unmarshal([]byte(readAll(b.do("GET", "/packages", nil))), &pk)
	resp := b.do("POST", "/accounts", map[string]any{"username": "imp1", "domain": "imp1.example", "package_id": pk.Items[0].ID, "password": "customer password 1"})
	if resp.StatusCode != 202 && resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, readAll(resp))
	}
	var acct struct{ ID string }
	json.Unmarshal([]byte(readAll(resp)), &acct)
	waitActive := func() {
		for i := 0; i < 200; i++ {
			var a struct{ Status string }
			json.Unmarshal([]byte(readAll(b.do("GET", "/accounts/"+acct.ID, nil))), &a)
			if a.Status == "active" {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("account never became active")
	}
	waitActive()

	// Signing in counts as a confirmation of the password.
	resp = b.do("POST", "/accounts/"+acct.ID+"/impersonate", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("impersonate: %d %s", resp.StatusCode, readAll(resp))
	}
	var lr struct {
		CSRFToken string `json:"csrf_token"`
	}
	json.Unmarshal([]byte(readAll(resp)), &lr)
	b.csrf = lr.CSRFToken

	resp = b.do("GET", "/me", nil)
	var me struct {
		Username, Role string
		ImpersonatorID string `json:"impersonator_id"`
	}
	json.Unmarshal([]byte(readAll(resp)), &me)
	if me.Username != "imp1" || me.Role != "user" || me.ImpersonatorID == "" {
		t.Fatalf("me: %+v", me)
	}
	// The customer's sign-in settings are out of reach.
	wantProblem(t, b.do("POST", "/me/password", map[string]string{"current_password": "customer password 1", "new_password": "a new long password"}), 403, "impersonating")
	wantProblem(t, b.do("POST", "/me/tokens", map[string]any{"name": "x", "scope": "read", "password": "customer password 1"}), 403, "impersonating")
	// And it is not an admin any more.
	wantProblem(t, b.do("GET", "/resellers", nil), 403, "forbidden")
}
