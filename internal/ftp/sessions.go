package ftp

import (
	"context"
	"time"

	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
)

// Session is one connection of an account's FTP login (ADR-0026).
type Session struct {
	PID      int32  `json:"pid"`
	Login    string `json:"login"`
	Seconds  int64  `json:"seconds"`
	State    string `json:"state"`
	File     string `json:"file"`
	Peer     string `json:"peer"`
	Current  int64  `json:"current"`
	Total    int64  `json:"total"`
	Percent  int32  `json:"percent"`
	BytesSec int64  `json:"bytes_per_sec"`
}

// loginNames returns the account's FTP login names (name@domain).
func (s *Service) loginNames(ctx context.Context, accountID string) (map[string]bool, error) {
	o, err := s.Overview(ctx, &auth.Principal{Login: &store.Login{Role: store.RoleAdmin}, Session: &store.Session{}}, accountID)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, l := range o.Logins {
		names[l.Login] = true
	}
	return names, nil
}

// Sessions lists the connections of the account's FTP logins (not other accounts').
func (s *Service) Sessions(ctx context.Context, p *auth.Principal, accountID string) ([]Session, error) {
	if _, _, err := s.access(ctx, p, accountID); err != nil {
		return nil, err
	}
	names, err := s.loginNames(ctx, accountID)
	if err != nil {
		return nil, err
	}
	res, err := s.agent.FTPSessions(ctx, &agentv1.FTPSessionsRequest{})
	if err != nil {
		return nil, err
	}
	out := []Session{}
	for _, x := range res.GetSessions() {
		if names[x.GetLogin()] {
			out = append(out, Session{
				PID: x.GetPid(), Login: x.GetLogin(), Seconds: x.GetSeconds(), State: x.GetState(), File: x.GetFile(), Peer: x.GetPeer(),
				Current: x.GetCurrent(), Total: x.GetTotal(), Percent: x.GetPercent(), BytesSec: x.GetBytesPerSec(),
			})
		}
	}
	return out, nil
}

// EndSession disconnects one of the account's FTP sessions.
func (s *Service) EndSession(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, pid int32) error {
	if _, _, err := s.forChange(ctx, p, accountID); err != nil {
		return err
	}
	list, err := s.Sessions(ctx, p, accountID)
	if err != nil {
		return err
	}
	for _, x := range list {
		if x.PID != pid {
			continue
		}
		res, err := s.agent.FTPSessionKill(ctx, &agentv1.FTPSessionKillRequest{Pid: pid, Login: x.Login})
		if err != nil {
			return err
		}
		if !res.GetEnded() {
			break
		}
		return s.audit.Record(ctx, event(c, p, "ftp.session.end", accountID, "", map[string]any{"login": x.Login, "peer": x.Peer, "at": time.Now().UTC().Format(time.RFC3339)}))
	}
	return store.ErrNotFound
}
