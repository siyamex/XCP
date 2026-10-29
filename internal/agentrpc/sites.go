package agentrpc

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

var canonicals = map[agentv1.Canonical]string{
	agentv1.Canonical_CANONICAL_UNSPECIFIED: "",
	agentv1.Canonical_CANONICAL_WWW:         agent.CanonicalWWW,
	agentv1.Canonical_CANONICAL_BARE:        agent.CanonicalBare,
}

func siteFrom(req *agentv1.SiteApplyRequest) agent.Site {
	s := agent.Site{
		Username: req.GetUsername(), UID: req.GetUid(),
		PHPVersion: req.GetPhpVersion(), Suspended: req.GetSuspended(), MaxChildren: req.GetMaxChildren(),
	}
	for _, v := range req.GetVhosts() {
		c, ok := canonicals[v.GetCanonical()]
		if !ok {
			c = "unknown" // refused by agent.CheckSite
		}
		vh := agent.Vhost{Name: v.GetName(), DocRoot: v.GetDocRoot(), Canonical: c, ForceHTTPS: v.GetForceHttps()}
		if t := v.GetTls(); t != nil {
			vh.TLS = &agent.TLS{CertPEM: t.GetCertPem(), KeyPEM: t.GetKeyPem()}
		}
		for _, r := range v.GetRedirects() {
			vh.Redirects = append(vh.Redirects, agent.Redirect{
				Path: r.GetPath(), Target: r.GetTarget(), Code: int(r.GetCode()), KeepPath: r.GetKeepPath(),
			})
		}
		s.Vhosts = append(s.Vhosts, vh)
	}
	return s
}

// SiteApply implements agentv1.AgentServiceServer.
func (s *Server) SiteApply(ctx context.Context, req *agentv1.SiteApplyRequest) (*agentv1.SiteApplyResponse, error) {
	res, err := s.Web.Apply(ctx, siteFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.SiteApplyResponse{Changed: res.Changed, PhpVersion: res.PHPVersion}, nil
}

// SiteRemove implements agentv1.AgentServiceServer.
func (s *Server) SiteRemove(ctx context.Context, req *agentv1.SiteRemoveRequest) (*agentv1.SiteRemoveResponse, error) {
	changed, err := s.Web.Remove(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.SiteRemoveResponse{Changed: changed}, nil
}

// PHPVersions implements agentv1.AgentServiceServer.
func (s *Server) PHPVersions(context.Context, *agentv1.PHPVersionsRequest) (*agentv1.PHPVersionsResponse, error) {
	return &agentv1.PHPVersionsResponse{Versions: s.Web.PHPVersions()}, nil
}

// fakeSites is the fake agent's view of web sites.
type fakeSites struct {
	mu    sync.Mutex
	sites map[string]agent.Site
}

// FakePHPVersions are the PHP versions the fake agent reports as installed.
var FakePHPVersions = []string{"8.2", "8.3"}

// Site returns the fake site of an account, for tests.
func (f *Fake) Site(username string) (agent.Site, bool) {
	f.sites.mu.Lock()
	defer f.sites.mu.Unlock()
	s, ok := f.sites.sites[username]
	return s, ok
}

// SiteApply implements Client.
func (f *Fake) SiteApply(_ context.Context, req *agentv1.SiteApplyRequest, _ ...grpc.CallOption) (*agentv1.SiteApplyResponse, error) {
	f.mu.Lock()
	site := siteFrom(req)
	names := make([]string, len(site.Vhosts))
	for i, v := range site.Vhosts {
		names[i] = v.Name
	}
	f.record("SiteApply %s %v php=%q suspended=%v", req.GetUsername(), names, req.GetPhpVersion(), req.GetSuspended())
	f.mu.Unlock()
	if err := agent.CheckSite(site); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if site.PHPVersion == "" {
		site.PHPVersion = FakePHPVersions[len(FakePHPVersions)-1]
	}
	if !slices.Contains(FakePHPVersions, site.PHPVersion) {
		return nil, status.Errorf(codes.InvalidArgument, "PHP %s is not installed", site.PHPVersion)
	}
	f.sites.mu.Lock()
	defer f.sites.mu.Unlock()
	if f.sites.sites == nil {
		f.sites.sites = map[string]agent.Site{}
	}
	f.sites.sites[site.Username] = site
	return &agentv1.SiteApplyResponse{Changed: true, PhpVersion: site.PHPVersion}, nil
}

// SiteRemove implements Client.
func (f *Fake) SiteRemove(_ context.Context, req *agentv1.SiteRemoveRequest, _ ...grpc.CallOption) (*agentv1.SiteRemoveResponse, error) {
	f.mu.Lock()
	f.record("SiteRemove %s", req.GetUsername())
	f.mu.Unlock()
	f.sites.mu.Lock()
	defer f.sites.mu.Unlock()
	_, ok := f.sites.sites[req.GetUsername()]
	delete(f.sites.sites, req.GetUsername())
	return &agentv1.SiteRemoveResponse{Changed: ok}, nil
}

// PHPVersions implements Client.
func (f *Fake) PHPVersions(context.Context, *agentv1.PHPVersionsRequest, ...grpc.CallOption) (*agentv1.PHPVersionsResponse, error) {
	return &agentv1.PHPVersionsResponse{Versions: slices.Clone(FakePHPVersions)}, nil
}
