package agentrpc

import (
	"context"
	"reflect"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/dnsrr"
)

func zoneFrom(req *agentv1.DNSZoneApplyRequest) agent.Zone {
	z := agent.Zone{Name: req.GetZone(), Nameservers: req.GetNameservers(), Hostmaster: req.GetHostmaster()}
	for _, r := range req.GetRecords() {
		z.Records = append(z.Records, dnsrr.Record{Name: r.GetName(), Type: r.GetType(), TTL: r.GetTtl(), Content: r.GetContent()})
	}
	return z
}

// DNSZoneApply implements agentv1.AgentServiceServer.
func (s *Server) DNSZoneApply(ctx context.Context, req *agentv1.DNSZoneApplyRequest) (*agentv1.DNSZoneApplyResponse, error) {
	do := s.DNS.Apply
	if req.GetDryRun() {
		do = s.DNS.Differs
	}
	changed, err := do(ctx, zoneFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.DNSZoneApplyResponse{Changed: changed}, nil
}

// DNSZoneDelete implements agentv1.AgentServiceServer.
func (s *Server) DNSZoneDelete(ctx context.Context, req *agentv1.DNSZoneDeleteRequest) (*agentv1.DNSZoneDeleteResponse, error) {
	deleted, err := s.DNS.Delete(ctx, req.GetZone())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.DNSZoneDeleteResponse{Deleted: deleted}, nil
}

// DNSZoneList implements agentv1.AgentServiceServer.
func (s *Server) DNSZoneList(ctx context.Context, _ *agentv1.DNSZoneListRequest) (*agentv1.DNSZoneListResponse, error) {
	zs, err := s.DNS.List(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.DNSZoneListResponse{Zones: zs}, nil
}

// fakeZones is the fake agent's view of DNS.
type fakeZones struct {
	mu    sync.Mutex
	zones map[string]agent.Zone
}

// SetZone makes the fake agent serve a zone as given, as if someone changed
// the DNS server behind the panel's back. For tests.
func (f *Fake) SetZone(z agent.Zone) {
	f.zones.mu.Lock()
	defer f.zones.mu.Unlock()
	if f.zones.zones == nil {
		f.zones.zones = map[string]agent.Zone{}
	}
	f.zones.zones[z.Name] = z
}

// Zone returns a zone the fake agent serves, for tests.
func (f *Fake) Zone(name string) (agent.Zone, bool) {
	f.zones.mu.Lock()
	defer f.zones.mu.Unlock()
	z, ok := f.zones.zones[name]
	return z, ok
}

// DNSZoneApply implements Client.
func (f *Fake) DNSZoneApply(_ context.Context, req *agentv1.DNSZoneApplyRequest, _ ...grpc.CallOption) (*agentv1.DNSZoneApplyResponse, error) {
	z := zoneFrom(req)
	if req.GetDryRun() {
		if err := agent.CheckZone(z); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		f.zones.mu.Lock()
		defer f.zones.mu.Unlock()
		have, ok := f.zones.zones[z.Name]
		return &agentv1.DNSZoneApplyResponse{Changed: !ok || !reflect.DeepEqual(have, z)}, nil
	}
	f.mu.Lock()
	f.record("DNSZoneApply %s (%d records)", req.GetZone(), len(req.GetRecords()))
	f.mu.Unlock()
	if err := agent.CheckZone(z); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	f.zones.mu.Lock()
	defer f.zones.mu.Unlock()
	if f.zones.zones == nil {
		f.zones.zones = map[string]agent.Zone{}
	}
	f.zones.zones[z.Name] = z
	return &agentv1.DNSZoneApplyResponse{Changed: true}, nil
}

// DNSZoneList implements Client.
func (f *Fake) DNSZoneList(context.Context, *agentv1.DNSZoneListRequest, ...grpc.CallOption) (*agentv1.DNSZoneListResponse, error) {
	f.zones.mu.Lock()
	defer f.zones.mu.Unlock()
	out := make([]string, 0, len(f.zones.zones))
	for n := range f.zones.zones {
		out = append(out, n)
	}
	slices.Sort(out)
	return &agentv1.DNSZoneListResponse{Zones: out}, nil
}

// DNSZoneDelete implements Client.
func (f *Fake) DNSZoneDelete(_ context.Context, req *agentv1.DNSZoneDeleteRequest, _ ...grpc.CallOption) (*agentv1.DNSZoneDeleteResponse, error) {
	f.mu.Lock()
	f.record("DNSZoneDelete %s", req.GetZone())
	f.mu.Unlock()
	f.zones.mu.Lock()
	defer f.zones.mu.Unlock()
	_, ok := f.zones.zones[req.GetZone()]
	delete(f.zones.zones, req.GetZone())
	return &agentv1.DNSZoneDeleteResponse{Deleted: ok}, nil
}
