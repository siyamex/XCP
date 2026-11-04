package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", "correct horse battery")
	p := e.principal(t, e.login(t, "root", "correct horse battery").Token)

	if _, err := e.svc.CreateToken(ctx, client, p, TokenInput{Name: "ci", Scope: "write", Password: "wrong password!!"}); err == nil {
		t.Fatal("a token was made without the right password")
	}
	for name, in := range map[string]TokenInput{
		"no name":  {Scope: "read", Password: "correct horse battery"},
		"scope":    {Name: "x", Scope: "root", Password: "correct horse battery"},
		"days":     {Name: "x", Scope: "read", ExpiresDays: 1000, Password: "correct horse battery"},
		"networks": {Name: "x", Scope: "read", IPAllow: []string{"nope"}, Password: "correct horse battery"},
	} {
		if _, err := e.svc.CreateToken(ctx, client, p, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	nt, err := e.svc.CreateToken(ctx, client, p, TokenInput{Name: "ci", Scope: "write", ExpiresDays: 2, IPAllow: []string{"203.0.113.0/24"}, Password: "correct horse battery"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(nt.Secret, "xcp_") || !strings.HasPrefix(nt.Secret, nt.Prefix) {
		t.Errorf("token %q prefix %q", nt.Secret, nt.Prefix)
	}
	list, _ := e.svc.ListTokens(ctx, p)
	if len(list) != 1 || list[0].Name != "ci" {
		t.Fatalf("list: %+v", list)
	}
	// The secret is not stored.
	if raw, _ := e.db.TokenByID(ctx, nt.ID); strings.Contains(string(raw.Hash), nt.Secret) || raw.Prefix == nt.Secret {
		t.Error("the secret is stored")
	}

	tp, err := e.svc.AuthenticateToken(ctx, nt.Secret, "203.0.113.5")
	if err != nil || tp.Login.Username != "root" || tp.Scope != store.TokenWrite {
		t.Fatalf("AuthenticateToken = %v, %v", tp, err)
	}
	if err := e.svc.RequireReauth(tp.Principal, time.Hour); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("a token passes the password confirmation: %v", err)
	}
	if _, err := e.svc.AuthenticateToken(ctx, nt.Secret, "198.51.100.1"); !errors.Is(err, ErrTokenIP) {
		t.Errorf("wrong address: %v", err)
	}
	bad := nt.Secret[:len(nt.Secret)-1] + "0"
	if bad == nt.Secret {
		bad = nt.Secret[:len(nt.Secret)-1] + "1"
	}
	for _, s := range []string{bad, "xcp_", "", "xcp_00000000_" + strings.Repeat("0", 48), nt.Secret + "0"} {
		if _, err := e.svc.AuthenticateToken(ctx, s, "203.0.113.5"); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%q: %v", s, err)
		}
	}

	e.now = e.now.Add(3 * 24 * time.Hour)
	if _, err := e.svc.AuthenticateToken(ctx, nt.Secret, "203.0.113.5"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expired token: %v", err)
	}
	e.now = e.now.Add(-3 * 24 * time.Hour)

	other := e.createAdmin(t, "other", "another horse battery")
	op := e.principal(t, e.login(t, "other", "another horse battery").Token)
	_ = other
	if err := e.svc.RevokeToken(ctx, client, op, nt.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("someone else revoked the token: %v", err)
	}
	if err := e.svc.RevokeToken(ctx, client, p, nt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AuthenticateToken(ctx, nt.Secret, "203.0.113.5"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("revoked token: %v", err)
	}
}
