package agentrpc

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func cronAccountFrom(req *agentv1.CronAccountApplyRequest) agent.CronAccount {
	a := agent.CronAccount{Username: req.GetUsername()}
	for _, j := range req.GetJobs() {
		a.Jobs = append(a.Jobs, agent.CronJob{ID: j.GetId(), Schedule: j.GetSchedule(), Command: j.GetCommand(), MailTo: j.GetMailTo()})
	}
	return a
}

func cronStatusFrom(runs map[string]agent.CronRun) *agentv1.CronStatusResponse {
	res := &agentv1.CronStatusResponse{}
	for _, id := range slices.Sorted(maps.Keys(runs)) {
		r := runs[id]
		res.Runs = append(res.Runs, &agentv1.CronRun{
			JobId: id, StartUnix: r.Start.Unix(), DurationMs: r.Duration.Milliseconds(),
			ExitCode: int32(r.ExitCode), Output: r.Output, Skipped: r.Skipped, //nolint:gosec // G115: an exit code
		})
	}
	return res
}

// CronAccountApply implements agentv1.AgentServiceServer.
func (s *Server) CronAccountApply(ctx context.Context, req *agentv1.CronAccountApplyRequest) (*agentv1.CronAccountApplyResponse, error) {
	changed, err := s.Cron.ApplyAccount(ctx, cronAccountFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.CronAccountApplyResponse{Changed: changed}, nil
}

// CronAccountRemove implements agentv1.AgentServiceServer.
func (s *Server) CronAccountRemove(ctx context.Context, req *agentv1.CronAccountRemoveRequest) (*agentv1.CronAccountRemoveResponse, error) {
	removed, err := s.Cron.RemoveAccount(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.CronAccountRemoveResponse{Removed: removed}, nil
}

// CronStatus implements agentv1.AgentServiceServer.
func (s *Server) CronStatus(ctx context.Context, req *agentv1.CronStatusRequest) (*agentv1.CronStatusResponse, error) {
	runs, err := s.Cron.Status(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return cronStatusFrom(runs), nil
}

// fakeCron is the fake agent's cron.
type fakeCron struct {
	mu       sync.Mutex
	accounts map[string]agent.CronAccount
	runs     map[string]map[string]agent.CronRun
}

// CronAccount returns the cron jobs the fake agent holds for an account, for tests.
func (f *Fake) CronAccount(username string) (agent.CronAccount, bool) {
	f.cron.mu.Lock()
	defer f.cron.mu.Unlock()
	a, ok := f.cron.accounts[username]
	return a, ok
}

// SetCronRun records a job's last run in the fake agent, for tests.
func (f *Fake) SetCronRun(username, id string, start time.Time, exitCode int, output string) {
	f.cron.mu.Lock()
	defer f.cron.mu.Unlock()
	if f.cron.runs == nil {
		f.cron.runs = map[string]map[string]agent.CronRun{}
	}
	if f.cron.runs[username] == nil {
		f.cron.runs[username] = map[string]agent.CronRun{}
	}
	f.cron.runs[username][id] = agent.CronRun{Start: start, Duration: time.Second, ExitCode: exitCode, Output: output}
}

// CronAccountApply implements Client.
func (f *Fake) CronAccountApply(_ context.Context, req *agentv1.CronAccountApplyRequest, _ ...grpc.CallOption) (*agentv1.CronAccountApplyResponse, error) {
	f.recordf("CronAccountApply %s (%d jobs)", req.GetUsername(), len(req.GetJobs()))
	a := cronAccountFrom(req)
	if err := agent.CheckCronAccount(a); err != nil {
		return nil, fakeInvalid(err)
	}
	f.cron.mu.Lock()
	defer f.cron.mu.Unlock()
	if f.cron.accounts == nil {
		f.cron.accounts = map[string]agent.CronAccount{}
	}
	f.cron.accounts[a.Username] = a
	return &agentv1.CronAccountApplyResponse{Changed: true}, nil
}

// CronAccountRemove implements Client.
func (f *Fake) CronAccountRemove(_ context.Context, req *agentv1.CronAccountRemoveRequest, _ ...grpc.CallOption) (*agentv1.CronAccountRemoveResponse, error) {
	f.recordf("CronAccountRemove %s", req.GetUsername())
	f.cron.mu.Lock()
	defer f.cron.mu.Unlock()
	_, ok := f.cron.accounts[req.GetUsername()]
	delete(f.cron.accounts, req.GetUsername())
	delete(f.cron.runs, req.GetUsername())
	return &agentv1.CronAccountRemoveResponse{Removed: ok}, nil
}

// CronStatus implements Client.
func (f *Fake) CronStatus(_ context.Context, req *agentv1.CronStatusRequest, _ ...grpc.CallOption) (*agentv1.CronStatusResponse, error) {
	f.cron.mu.Lock()
	defer f.cron.mu.Unlock()
	return cronStatusFrom(f.cron.runs[req.GetUsername()]), nil
}
