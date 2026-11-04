package agentrpc

import (
	"bytes"
	"context"
	"sync"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// BackupInspect implements agentv1.AgentServiceServer.
func (s *Server) BackupInspect(_ context.Context, req *agentv1.BackupInspectRequest) (*agentv1.BackupInspectResponse, error) {
	plan, err := s.Backups.Inspect(req.GetUsername(), req.GetFile())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupInspectResponse{AccountJson: plan.AccountJSON, Databases: plan.Databases, Files: plan.Files, Bytes: plan.Bytes, PanelVersion: plan.Panel}, nil
}

// BackupRestoreHome implements agentv1.AgentServiceServer.
func (s *Server) BackupRestoreHome(ctx context.Context, req *agentv1.BackupRestoreRequest) (*agentv1.BackupRestoreHomeResponse, error) {
	n, err := s.Backups.RestoreHome(ctx, req.GetUsername(), req.GetFile())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRestoreHomeResponse{Entries: n}, nil
}

// BackupRestoreDatabases implements agentv1.AgentServiceServer.
func (s *Server) BackupRestoreDatabases(ctx context.Context, req *agentv1.BackupRestoreRequest) (*agentv1.BackupRestoreDatabasesResponse, error) {
	dbs, err := s.Backups.RestoreDatabases(ctx, req.GetUsername(), req.GetFile(), s.MySQL)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRestoreDatabasesResponse{Databases: dbs}, nil
}

// HostnameSet implements agentv1.AgentServiceServer.
func (s *Server) HostnameSet(ctx context.Context, req *agentv1.HostnameSetRequest) (*agentv1.HostnameSetResponse, error) {
	if err := s.HostConfig.SetHostname(ctx, req.GetHostname()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.HostnameSetResponse{}, nil
}

// TimezoneSet implements agentv1.AgentServiceServer.
func (s *Server) TimezoneSet(ctx context.Context, req *agentv1.TimezoneSetRequest) (*agentv1.TimezoneSetResponse, error) {
	if err := s.HostConfig.SetTimezone(ctx, req.GetTimezone()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.TimezoneSetResponse{}, nil
}

// OSUpdatesSet implements agentv1.AgentServiceServer.
func (s *Server) OSUpdatesSet(ctx context.Context, req *agentv1.OSUpdatesSetRequest) (*agentv1.OSUpdatesSetResponse, error) {
	changed, err := s.HostConfig.SetOSUpdates(ctx, req.GetEnabled())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.OSUpdatesSetResponse{Changed: changed}, nil
}

// ServerReboot implements agentv1.AgentServiceServer.
func (s *Server) ServerReboot(ctx context.Context, req *agentv1.ServerRebootRequest) (*agentv1.ServerRebootResponse, error) {
	if err := s.HostConfig.Reboot(ctx, req.GetForce()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.ServerRebootResponse{}, nil
}

// fakeHost is the fake agent's host settings.
type fakeHost struct {
	mu       sync.Mutex
	hostname string
	timezone string
	osAuto   bool
	reboots  []bool // force flags
}

// Host returns the host settings the fake agent was given, for tests.
func (f *Fake) Host() (hostname, timezone string, osAuto bool, reboots []bool) {
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	return f.host.hostname, f.host.timezone, f.host.osAuto, append([]bool(nil), f.host.reboots...)
}

// BackupInspect implements Client: the fake keeps only account.json.
func (f *Fake) BackupInspect(_ context.Context, req *agentv1.BackupInspectRequest, _ ...grpc.CallOption) (*agentv1.BackupInspectResponse, error) {
	f.recordf("BackupInspect %s %s", req.GetUsername(), req.GetFile())
	if err := agent.CheckBackupFile(req.GetUsername(), req.GetFile()); err != nil {
		return nil, fakeInvalid(err)
	}
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	c, ok := f.backups.files[req.GetUsername()][req.GetFile()]
	if !ok {
		return nil, fakeNotFound("no such backup")
	}
	return &agentv1.BackupInspectResponse{AccountJson: bytes.TrimLeft(c, "#"), PanelVersion: "fake"}, nil
}

// BackupRestoreHome implements Client.
func (f *Fake) BackupRestoreHome(_ context.Context, req *agentv1.BackupRestoreRequest, _ ...grpc.CallOption) (*agentv1.BackupRestoreHomeResponse, error) {
	f.recordf("BackupRestoreHome %s %s", req.GetUsername(), req.GetFile())
	return &agentv1.BackupRestoreHomeResponse{Entries: 1}, nil
}

// BackupRestoreDatabases implements Client.
func (f *Fake) BackupRestoreDatabases(_ context.Context, req *agentv1.BackupRestoreRequest, _ ...grpc.CallOption) (*agentv1.BackupRestoreDatabasesResponse, error) {
	f.recordf("BackupRestoreDatabases %s %s", req.GetUsername(), req.GetFile())
	return &agentv1.BackupRestoreDatabasesResponse{}, nil
}

// HostnameSet implements Client.
func (f *Fake) HostnameSet(_ context.Context, req *agentv1.HostnameSetRequest, _ ...grpc.CallOption) (*agentv1.HostnameSetResponse, error) {
	f.recordf("HostnameSet %s", req.GetHostname())
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	f.host.hostname = req.GetHostname()
	return &agentv1.HostnameSetResponse{}, nil
}

// TimezoneSet implements Client.
func (f *Fake) TimezoneSet(_ context.Context, req *agentv1.TimezoneSetRequest, _ ...grpc.CallOption) (*agentv1.TimezoneSetResponse, error) {
	f.recordf("TimezoneSet %s", req.GetTimezone())
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	f.host.timezone = req.GetTimezone()
	return &agentv1.TimezoneSetResponse{}, nil
}

// OSUpdatesSet implements Client.
func (f *Fake) OSUpdatesSet(_ context.Context, req *agentv1.OSUpdatesSetRequest, _ ...grpc.CallOption) (*agentv1.OSUpdatesSetResponse, error) {
	f.recordf("OSUpdatesSet %v", req.GetEnabled())
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	changed := f.host.osAuto != req.GetEnabled()
	f.host.osAuto = req.GetEnabled()
	return &agentv1.OSUpdatesSetResponse{Changed: changed}, nil
}

// ServerReboot implements Client.
func (f *Fake) ServerReboot(_ context.Context, req *agentv1.ServerRebootRequest, _ ...grpc.CallOption) (*agentv1.ServerRebootResponse, error) {
	f.recordf("ServerReboot force=%v", req.GetForce())
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	f.host.reboots = append(f.host.reboots, req.GetForce())
	return &agentv1.ServerRebootResponse{}, nil
}
