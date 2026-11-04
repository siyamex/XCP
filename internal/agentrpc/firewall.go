package agentrpc

import (
	"context"
	"sync"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func fwPorts(in []*agentv1.FirewallPort) []agent.FWPort {
	out := make([]agent.FWPort, len(in))
	for i, p := range in {
		out[i] = agent.FWPort{Port: p.GetPort(), Proto: p.GetProto()}
	}
	return out
}

func firewallRulesFrom(req *agentv1.FirewallApplyRequest) agent.FirewallRules {
	r := agent.FirewallRules{
		Enabled: req.GetEnabled(), Closed: req.GetClosed(), OpenPorts: fwPorts(req.GetOpenPorts()), Allow: req.GetAllow(), Deny: req.GetDeny(),
		RateEnabled: req.GetRateLimit(), RatePerMin: int(req.GetRatePerMinute()), RatePorts: fwPorts(req.GetRatePorts()),
	}
	for _, b := range req.GetBans() {
		r.Bans = append(r.Bans, agent.FWBan{IP: b.GetIp(), Seconds: b.GetSeconds()})
	}
	for _, rs := range req.GetRestrictions() {
		r.Restrictions = append(r.Restrictions, agent.FWRestriction{Name: rs.GetName(), Ports: fwPorts(rs.GetPorts()), Allowed: rs.GetAllowed()})
	}
	return r
}

// FirewallApply implements agentv1.AgentServiceServer.
func (s *Server) FirewallApply(ctx context.Context, req *agentv1.FirewallApplyRequest) (*agentv1.FirewallApplyResponse, error) {
	changed, err := s.Firewall.Apply(ctx, firewallRulesFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FirewallApplyResponse{Changed: changed}, nil
}

// fakeFirewall is the fake agent's firewall: the last rules it was given.
type fakeFirewall struct {
	mu    sync.Mutex
	rules *agent.FirewallRules
}

// Firewall returns the rules the fake agent last applied, for tests.
func (f *Fake) Firewall() *agent.FirewallRules {
	f.fw.mu.Lock()
	defer f.fw.mu.Unlock()
	return f.fw.rules
}

// FirewallApply implements Client.
func (f *Fake) FirewallApply(_ context.Context, req *agentv1.FirewallApplyRequest, _ ...grpc.CallOption) (*agentv1.FirewallApplyResponse, error) {
	f.recordf("FirewallApply enabled=%v", req.GetEnabled())
	r := firewallRulesFrom(req)
	if err := r.Check(); err != nil {
		return nil, fakeInvalid(err)
	}
	f.fw.mu.Lock()
	defer f.fw.mu.Unlock()
	f.fw.rules = &r
	return &agentv1.FirewallApplyResponse{Changed: true}, nil
}
