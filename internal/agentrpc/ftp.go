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
