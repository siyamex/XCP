package agentrpc

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/tlsx"
)

// HostCertificateInstall implements agentv1.AgentServiceServer.
func (s *Server) HostCertificateInstall(ctx context.Context, req *agentv1.HostCertificateInstallRequest) (*agentv1.HostCertificateInstallResponse, error) {
	t := req.GetTls()
	changed, err := s.HostCert.InstallCertificate(req.GetHostname(), agent.TLS{CertPEM: t.GetCertPem(), KeyPEM: t.GetKeyPem()})
	if err != nil {
		return nil, s.toStatus(err)
	}
	if changed {
		// Apache serves it on the host name too (phpMyAdmin, ADR-0006). The
		// certificate is in place either way, so a failed reload only waits
		// for the next one.
		if err := s.Services.Do(ctx, "web", agent.ActionReload); err != nil {
			s.Log.Warn("reload Apache for the new host name certificate", "err", err)
		}
		if s.Mail != nil {
			if _, err := s.Mail.RefreshTLS(ctx); err != nil {
				s.Log.Warn("give mail the new host name certificate", "err", err)
			}
		}
		if s.FTP != nil {
			if _, err := s.FTP.RefreshTLS(ctx); err != nil {
				s.Log.Warn("give FTP the new host name certificate", "err", err)
			}
		}
	}
	return &agentv1.HostCertificateInstallResponse{Changed: changed}, nil
}

// HostCertificate returns the host name certificate the fake agent installed, for tests.
func (f *Fake) HostCertificate() (hostname, certPEM string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostName, f.hostCert
}

// HostCertificateInstall implements Client.
func (f *Fake) HostCertificateInstall(_ context.Context, req *agentv1.HostCertificateInstallRequest, _ ...grpc.CallOption) (*agentv1.HostCertificateInstallResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("HostCertificateInstall %s", req.GetHostname())
	t := req.GetTls()
	p, err := tlsx.Parse(t.GetCertPem(), "", t.GetKeyPem())
	if err != nil || !tlsx.Covers(p.Leaf, req.GetHostname()) || !tlsx.Valid(p.Leaf, time.Now()) {
		return nil, status.Errorf(codes.InvalidArgument, "panel certificate refused: %v", err)
	}
	changed := f.hostCert != p.CertPEM
	f.hostName, f.hostCert = req.GetHostname(), p.CertPEM
	return &agentv1.HostCertificateInstallResponse{Changed: changed}, nil
}
