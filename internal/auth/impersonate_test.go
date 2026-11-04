package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

func TestImpersonate(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", "correct horse battery")
	p := e.principal(t, e.login(t, "root", "correct horse battery").Token)
	target, err := e.svc.CreateLogin(ctx, client, p, NewLogin{Username: "alice", Password: "another horse battery", Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	// Recent password confirmation is needed.
	e.now = e.now.Add(10 * time.Minute)
	if _, err := e.svc.Impersonate(ctx, client, p, target); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("without a recent confirmation: %v", err)
	}
	if err := e.svc.Reauth(ctx, client, p, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	token, err := e.svc.Impersonate(ctx, client, p, target)
	if err != nil {
		t.Fatal(err)
	}
	ip := e.principal(t, token)
	if ip.Login.Username != "alice" || ip.Session.ImpersonatorID != p.Login.ID {
		t.Errorf("session: %+v", ip.Session)
	}
	// It ends within the hour, however active.
	e.now = e.now.Add(ImpersonationMax + time.Minute)
	if _, err := e.svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("an impersonation outlived its hour: %v", err)
	}

	// No chaining, no admins or resellers as targets, no suspended targets.
	e.now = e.now.Add(-ImpersonationMax - time.Minute)
	if _, err := e.svc.Impersonate(ctx, client, ip, target); !errors.Is(err, ErrNoImpersonation) {
		t.Errorf("chained impersonation: %v", err)
	}
	admin2 := e.createAdmin(t, "root2", "yet another horse")
	if _, err := e.svc.Impersonate(ctx, client, p, admin2); !errors.Is(err, ErrNoImpersonation) {
		t.Errorf("impersonating an admin: %v", err)
	}
	// A user cannot start one.
	up := e.principal(t, e.login(t, "alice", "another horse battery").Token)
	if _, err := e.svc.Impersonate(ctx, client, up, target); !errors.Is(err, ErrNoImpersonation) {
		t.Errorf("a user impersonating: %v", err)
	}
}
