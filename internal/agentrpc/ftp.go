package agentrpc

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func ftpAccountFrom(req *agentv1.FTPAccountApplyRequest) agent.FTPAccount {
	a := agent.FTPAccount{Username: req.GetUsername()}
	for _, l := range req.GetLogins() {
		a.Logins = append(a.Logins, agent.FTPLogin{Login: l.GetLogin(), PasswordHash: l.GetPasswordHash(), Dir: l.GetDir(), QuotaMB: l.GetQuotaMb()})
	}
	return a
}

// FTPAccountApply implements agentv1.AgentServiceServer.
func (s *Server) FTPAccountApply(ctx context.Context, req *agentv1.FTPAccountApplyRequest) (*agentv1.FTPAccountApplyResponse, error) {
	changed, problems, err := s.FTP.ApplyAccount(ctx, ftpAccountFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FTPAccountApplyResponse{Changed: changed, Problems: problems}, nil
}

// FTPAccountRemove implements agentv1.AgentServiceServer.
func (s *Server) FTPAccountRemove(ctx context.Context, req *agentv1.FTPAccountRemoveRequest) (*agentv1.FTPAccountRemoveResponse, error) {
	removed, err := s.FTP.RemoveAccount(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FTPAccountRemoveResponse{Removed: removed}, nil
}

// fakeFTP is the fake agent's FTP server.
type fakeFTP struct {
	mu       sync.Mutex
	accounts map[string]agent.FTPAccount
	sessions []*agentv1.FTPSession
}

// FTPAccount returns the FTP logins the fake agent holds for an account, for tests.
func (f *Fake) FTPAccount(username string) (agent.FTPAccount, bool) {
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	a, ok := f.ftp.accounts[username]
	return a, ok
}

// FTPAccountApply implements Client.
func (f *Fake) FTPAccountApply(_ context.Context, req *agentv1.FTPAccountApplyRequest, _ ...grpc.CallOption) (*agentv1.FTPAccountApplyResponse, error) {
	f.recordf("FTPAccountApply %s (%d logins)", req.GetUsername(), len(req.GetLogins()))
	a := ftpAccountFrom(req)
	if err := agent.CheckFTPAccount(a); err != nil {
		return nil, fakeInvalid(err)
	}
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	if f.ftp.accounts == nil {
		f.ftp.accounts = map[string]agent.FTPAccount{}
	}
	for name, o := range f.ftp.accounts {
		if name == a.Username {
			continue
		}
		for _, ol := range o.Logins {
			for _, l := range a.Logins {
				if l.Login == ol.Login {
					return nil, fakeInvalid(fmt.Errorf("FTP login %s belongs to account %s", l.Login, name))
				}
			}
		}
	}
	f.ftp.accounts[a.Username] = a
	return &agentv1.FTPAccountApplyResponse{Changed: true}, nil
}

// FTPAccountRemove implements Client.
func (f *Fake) FTPAccountRemove(_ context.Context, req *agentv1.FTPAccountRemoveRequest, _ ...grpc.CallOption) (*agentv1.FTPAccountRemoveResponse, error) {
	f.recordf("FTPAccountRemove %s", req.GetUsername())
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	_, ok := f.ftp.accounts[req.GetUsername()]
	delete(f.ftp.accounts, req.GetUsername())
	return &agentv1.FTPAccountRemoveResponse{Removed: ok}, nil
}

// FTPSessions implements agentv1.AgentServiceServer.
func (s *Server) FTPSessions(ctx context.Context, _ *agentv1.FTPSessionsRequest) (*agentv1.FTPSessionsResponse, error) {
	list, err := s.FTP.Sessions(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	out := &agentv1.FTPSessionsResponse{}
	for _, x := range list {
		out.Sessions = append(out.Sessions, &agentv1.FTPSession{
			Pid: int32(x.PID), Login: x.Login, Seconds: x.Seconds, State: x.State, File: x.File, Peer: x.Peer, //nolint:gosec // G115: a pid fits
			Current: x.Current, Total: x.Total, Percent: int32(x.Percent), BytesPerSec: x.BytesSec, //nolint:gosec // G115: 0..100
		})
	}
	return out, nil
}

// FTPSessionKill implements agentv1.AgentServiceServer.
func (s *Server) FTPSessionKill(ctx context.Context, req *agentv1.FTPSessionKillRequest) (*agentv1.FTPSessionKillResponse, error) {
	ended, err := s.FTP.Kill(ctx, int(req.GetPid()), req.GetLogin())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FTPSessionKillResponse{Ended: ended}, nil
}

// FTPSession puts a connection in the fake FTP server, for tests.
func (f *Fake) FTPSession(pid int32, login, peer string) {
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	f.ftp.sessions = append(f.ftp.sessions, &agentv1.FTPSession{Pid: pid, Login: login, Peer: peer, State: "IDLE", Seconds: 12})
}

// FTPSessions implements Client.
func (f *Fake) FTPSessions(_ context.Context, _ *agentv1.FTPSessionsRequest, _ ...grpc.CallOption) (*agentv1.FTPSessionsResponse, error) {
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	return &agentv1.FTPSessionsResponse{Sessions: append([]*agentv1.FTPSession(nil), f.ftp.sessions...)}, nil
}

// FTPSessionKill implements Client.
func (f *Fake) FTPSessionKill(_ context.Context, req *agentv1.FTPSessionKillRequest, _ ...grpc.CallOption) (*agentv1.FTPSessionKillResponse, error) {
	f.recordf("FTPSessionKill %d %s", req.GetPid(), req.GetLogin())
	f.ftp.mu.Lock()
	defer f.ftp.mu.Unlock()
	for i, s := range f.ftp.sessions {
		if s.Pid == req.GetPid() && s.Login == req.GetLogin() {
			f.ftp.sessions = append(f.ftp.sessions[:i], f.ftp.sessions[i+1:]...)
			return &agentv1.FTPSessionKillResponse{Ended: true}, nil
		}
	}
	return &agentv1.FTPSessionKillResponse{}, nil
}
