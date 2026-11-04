package serverinfo

import (
	"context"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/validate"
)

// SetHooks connects what a reboot and a rebuild need from other services:
// checking the admin's password again, and queueing the apply of everything.
func (s *Service) SetHooks(reauth func(ctx context.Context, c auth.Client, p *auth.Principal, password string) error,
	rebuild func(ctx context.Context, by string) (map[string]int, error),
) {
	s.reauth, s.rebuild = reauth, rebuild
}

// Reboot restarts the server in a few seconds (ADM-SRV-08). mode is
// "graceful" (services stop in order) or "forced" (no orderly shutdown).
// The admin proves it is them by typing their password again.
func (s *Service) Reboot(ctx context.Context, c auth.Client, p *auth.Principal, mode, password string) error {
	if err := admin(p); err != nil {
		return err
	}
	if mode != "graceful" && mode != "forced" {
		return &validate.Error{Field: "mode", Code: validate.CodeFormat, Message: "graceful or forced"}
	}
	if s.reauth != nil {
		if err := s.reauth(ctx, c, p, password); err != nil {
			return err
		}
	}
	// Recorded first: after the reboot there is no one to record it.
	if err := s.audit.Record(ctx, event(c, p, "server.reboot", "server", "server", map[string]any{"mode": mode})); err != nil {
		return err
	}
	_, err := s.agent.ServerReboot(ctx, &agentv1.ServerRebootRequest{Force: mode == "forced"})
	return err
}

// Rebuild queues everything that makes the server match the panel's
// database again: every account, every DNS zone and the mail server's
// settings (ADM-SRV-xx, "xcpctl rebuild"). It reports what it queued.
func (s *Service) Rebuild(ctx context.Context, c auth.Client, p *auth.Principal) (map[string]int, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	if s.rebuild == nil {
		return nil, nil
	}
	res, err := s.rebuild(ctx, p.Login.ID)
	if err != nil {
		return nil, err
	}
	return res, s.audit.Record(ctx, event(c, p, "server.rebuild", "server", "server", map[string]any{"queued": res}))
}
