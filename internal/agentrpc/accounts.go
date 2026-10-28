package agentrpc

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func shellFrom(s agentv1.Shell) agent.Shell {
	switch s {
	case agentv1.Shell_SHELL_JAILED:
		return agent.ShellJailed
	case agentv1.Shell_SHELL_FULL:
		return agent.ShellFull
	}
	return agent.ShellNone
}

func limitsFrom(l *agentv1.ResourceLimits) agent.Limits {
	if l == nil {
		return agent.Limits{}
	}
	return agent.Limits{CPUPercent: l.CpuPercent, MemoryMB: l.MemoryMb, Tasks: l.Tasks, DiskMB: l.DiskMb, Inodes: l.Inodes}
}

// AccountEnsure implements agentv1.AgentServiceServer.
func (s *Server) AccountEnsure(ctx context.Context, req *agentv1.AccountEnsureRequest) (*agentv1.AccountEnsureResponse, error) {
	res, err := s.Accounts.Ensure(ctx, req.GetUsername(), req.GetUid(), shellFrom(req.GetShell()), limitsFrom(req.GetLimits()), req.GetPrimaryDomain())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.AccountEnsureResponse{Created: res.Created, QuotaApplied: res.QuotaApplied, Home: res.Home}, nil
}

// AccountSetSuspended implements agentv1.AgentServiceServer.
func (s *Server) AccountSetSuspended(ctx context.Context, req *agentv1.AccountSetSuspendedRequest) (*agentv1.AccountSetSuspendedResponse, error) {
	if err := s.Accounts.SetSuspended(ctx, req.GetUsername(), req.GetSuspended(), shellFrom(req.GetShell())); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.AccountSetSuspendedResponse{}, nil
}

// AccountDelete implements agentv1.AgentServiceServer.
func (s *Server) AccountDelete(ctx context.Context, req *agentv1.AccountDeleteRequest) (*agentv1.AccountDeleteResponse, error) {
	deleted, err := s.Accounts.Delete(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.AccountDeleteResponse{Deleted: deleted}, nil
}

// fakeUsers is the fake agent's view of Linux users.
type fakeUsers struct {
	mu    sync.Mutex
	users map[string]FakeUser
}

// FakeUser is a Linux user as the fake agent remembers it.
type FakeUser struct {
	UID       uint32
	Shell     agentv1.Shell
	Suspended bool
	Limits    agent.Limits
}

// User returns the fake Linux user, for tests.
func (f *Fake) User(name string) (FakeUser, bool) {
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	u, ok := f.accounts.users[name]
	return u, ok
}

func notOurs() error { return status.Error(codes.FailedPrecondition, agent.ErrNotOurUser.Error()) }

// AccountEnsure implements Client.
func (f *Fake) AccountEnsure(_ context.Context, req *agentv1.AccountEnsureRequest, _ ...grpc.CallOption) (*agentv1.AccountEnsureResponse, error) {
	f.mu.Lock()
	f.record("AccountEnsure %s uid=%d", req.GetUsername(), req.GetUid())
	f.mu.Unlock()
	if err := agent.CheckAccount(req.GetUsername(), req.GetUid(), req.GetPrimaryDomain()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	if f.accounts.users == nil {
		f.accounts.users = map[string]FakeUser{}
	}
	u, exists := f.accounts.users[req.GetUsername()]
	if exists && u.UID != req.GetUid() {
		return nil, notOurs()
	}
	for name, other := range f.accounts.users {
		if other.UID == req.GetUid() && name != req.GetUsername() {
			return nil, notOurs()
		}
	}
	u.UID, u.Shell, u.Limits = req.GetUid(), req.GetShell(), limitsFrom(req.GetLimits())
	f.accounts.users[req.GetUsername()] = u
	return &agentv1.AccountEnsureResponse{Created: !exists, Home: "/home/" + req.GetUsername()}, nil
}

// AccountSetSuspended implements Client.
func (f *Fake) AccountSetSuspended(_ context.Context, req *agentv1.AccountSetSuspendedRequest, _ ...grpc.CallOption) (*agentv1.AccountSetSuspendedResponse, error) {
	f.mu.Lock()
	f.record("AccountSetSuspended %s %v", req.GetUsername(), req.GetSuspended())
	f.mu.Unlock()
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	u, ok := f.accounts.users[req.GetUsername()]
	if !ok {
		return nil, notOurs()
	}
	u.Suspended = req.GetSuspended()
	if !u.Suspended {
		u.Shell = req.GetShell()
	}
	f.accounts.users[req.GetUsername()] = u
	return &agentv1.AccountSetSuspendedResponse{}, nil
}

// AccountDelete implements Client.
func (f *Fake) AccountDelete(_ context.Context, req *agentv1.AccountDeleteRequest, _ ...grpc.CallOption) (*agentv1.AccountDeleteResponse, error) {
	f.mu.Lock()
	f.record("AccountDelete %s", req.GetUsername())
	f.mu.Unlock()
	f.accounts.mu.Lock()
	defer f.accounts.mu.Unlock()
	_, ok := f.accounts.users[req.GetUsername()]
	delete(f.accounts.users, req.GetUsername())
	return &agentv1.AccountDeleteResponse{Deleted: ok}, nil
}
