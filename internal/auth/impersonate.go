package auth

import (
	"context"
	"errors"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

// Impersonation (RSL-ACC-05, ADR-0024): an admin or a reseller signs in as
// the user of an account it manages, to help or to check. The session is
// marked with who started it, lasts an hour at most, and every audit event
// made through it names both.
const (
	ImpersonationMax    = time.Hour
	impersonationReauth = 5 * time.Minute
)

// ErrNoImpersonation is returned when the target cannot be impersonated.
var ErrNoImpersonation = errors.New("this login cannot be impersonated")

// Impersonate starts a session as target for actor and returns its token.
// The caller has checked that the actor manages the target's account. The
// actor must have confirmed its password in the last five minutes, and a
// session that is itself an impersonation cannot start another.
func (s *Service) Impersonate(ctx context.Context, c Client, actor *Principal, target *store.Login) (string, error) {
	if actor.Session.ImpersonatorID != "" {
		return "", ErrNoImpersonation
	}
	if actor.Login.Role != store.RoleAdmin && actor.Login.Role != store.RoleReseller {
		return "", ErrNoImpersonation
	}
	if target.Role != store.RoleUser || target.Status != store.LoginActive {
		return "", ErrNoImpersonation
	}
	if err := s.RequireReauth(actor, impersonationReauth); err != nil {
		return "", err
	}
	now := s.now()
	token, idHash := newToken()
	exp := now.Add(ImpersonationMax)
	if m := now.Add(s.sessionMax()); m.Before(exp) {
		exp = m
	}
	sess := &store.Session{
		IDHash: idHash, LoginID: target.ID, ImpersonatorID: actor.Login.ID, MFAPassed: true, IP: c.IP,
		UserAgent: truncate(c.UserAgent, 512), CreatedAt: now, LastSeenAt: now, ExpiresAt: exp,
	}
	if err := s.db.CreateSession(ctx, sess); err != nil {
		return "", err
	}
	ev := s.event(c, actor, "auth.impersonate", map[string]any{"target": target.Username, "account_id": target.AccountID})
	ev.TargetID, ev.AccountID = target.ID, target.AccountID
	if err := s.audit.Record(ctx, ev); err != nil {
		return "", err
	}
	return token, nil
}
