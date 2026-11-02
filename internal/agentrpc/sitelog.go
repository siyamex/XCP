package agentrpc

import (
	"context"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// SiteLogTail implements agentv1.AgentServiceServer.
func (s *Server) SiteLogTail(_ context.Context, req *agentv1.SiteLogTailRequest) (*agentv1.SiteLogTailResponse, error) {
	lines, err := s.Web.TailLog(req.GetUsername(), req.GetKind(), int(req.GetLines()), req.GetContains())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.SiteLogTailResponse{Lines: lines}, nil
}

// SiteLogRead implements agentv1.AgentServiceServer.
func (s *Server) SiteLogRead(_ context.Context, req *agentv1.SiteLogReadRequest) (*agentv1.SiteLogReadResponse, error) {
	data, size, err := s.Web.ReadLog(req.GetUsername(), req.GetKind(), req.GetOffset(), req.GetLength())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.SiteLogReadResponse{Data: data, Size: size}, nil
}

// fakeLogs are the fake agent's site logs, set by tests.
type fakeLogs struct {
	mu   sync.Mutex
	logs map[string]string // "<user>.<kind>"
}

// SetSiteLog sets an account's log in the fake agent, for tests.
func (f *Fake) SetSiteLog(username, kind, content string) {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	if f.logs.logs == nil {
		f.logs.logs = map[string]string{}
	}
	f.logs.logs[username+"."+kind] = content
}

// SiteLogTail implements Client.
func (f *Fake) SiteLogTail(_ context.Context, req *agentv1.SiteLogTailRequest, _ ...grpc.CallOption) (*agentv1.SiteLogTailResponse, error) {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	var out []string
	for _, l := range strings.Split(f.logs.logs[req.GetUsername()+"."+req.GetKind()], "\n") {
		if l != "" && strings.Contains(l, req.GetContains()) {
			out = append(out, l)
		}
	}
	if n := int(req.GetLines()); len(out) > n {
		out = out[len(out)-n:]
	}
	return &agentv1.SiteLogTailResponse{Lines: out}, nil
}

// SiteLogRead implements Client.
func (f *Fake) SiteLogRead(_ context.Context, req *agentv1.SiteLogReadRequest, _ ...grpc.CallOption) (*agentv1.SiteLogReadResponse, error) {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	log := f.logs.logs[req.GetUsername()+"."+req.GetKind()]
	off := min(int(req.GetOffset()), len(log))
	end := min(off+int(req.GetLength()), len(log))
	return &agentv1.SiteLogReadResponse{Data: []byte(log[off:end]), Size: int64(len(log))}, nil
}
