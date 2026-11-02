package agentrpc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// BackupCreate implements agentv1.AgentServiceServer.
func (s *Server) BackupCreate(ctx context.Context, req *agentv1.BackupCreateRequest) (*agentv1.BackupCreateResponse, error) {
	res, err := s.Backups.Create(ctx, agent.BackupRequest{Username: req.GetUsername(), AccountJSON: req.GetAccountJson(), Databases: req.GetDatabases()})
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupCreateResponse{File: res.File, Size: res.Size, Sha256: res.SHA256, Skipped: res.Skipped}, nil
}

// BackupRead implements agentv1.AgentServiceServer.
func (s *Server) BackupRead(_ context.Context, req *agentv1.BackupReadRequest) (*agentv1.BackupReadResponse, error) {
	data, size, err := s.Backups.Read(req.GetUsername(), req.GetFile(), req.GetOffset(), req.GetLength())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupReadResponse{Data: data, Size: size}, nil
}

// BackupDelete implements agentv1.AgentServiceServer.
func (s *Server) BackupDelete(_ context.Context, req *agentv1.BackupDeleteRequest) (*agentv1.BackupDeleteResponse, error) {
	ok, err := s.Backups.Delete(req.GetUsername(), req.GetFile())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupDeleteResponse{Deleted: ok}, nil
}

// BackupRemoveAccount implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoveAccount(_ context.Context, req *agentv1.BackupRemoveAccountRequest) (*agentv1.BackupRemoveAccountResponse, error) {
	ok, err := s.Backups.RemoveAccount(req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRemoveAccountResponse{Removed: ok}, nil
}

// fakeBackups are the fake agent's backups: the account.json each holds.
type fakeBackups struct {
	mu    sync.Mutex
	files map[string]map[string][]byte // user -> file -> content
	n     int
	fail  string // set: BackupCreate fails with this
}

// Backups returns the fake agent's backups of an account, for tests.
func (f *Fake) Backups(username string) map[string][]byte {
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.backups.files[username] {
		out[k] = v
	}
	return out
}

// FailBackups makes BackupCreate fail with msg ("" to stop), for tests.
func (f *Fake) FailBackups(msg string) {
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	f.backups.fail = msg
}

// BackupCreate implements Client.
func (f *Fake) BackupCreate(_ context.Context, req *agentv1.BackupCreateRequest, _ ...grpc.CallOption) (*agentv1.BackupCreateResponse, error) {
	f.recordf("BackupCreate %s (%d databases)", req.GetUsername(), len(req.GetDatabases()))
	for _, db := range req.GetDatabases() {
		if err := agent.CheckMySQLName(req.GetUsername(), db, agent.MaxDatabaseName); err != nil {
			return nil, fakeInvalid(err)
		}
	}
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	if f.backups.fail != "" {
		return nil, fmt.Errorf("%s", f.backups.fail)
	}
	if f.backups.files == nil {
		f.backups.files = map[string]map[string][]byte{}
	}
	if f.backups.files[req.GetUsername()] == nil {
		f.backups.files[req.GetUsername()] = map[string][]byte{}
	}
	// Distinct names even within one second.
	f.backups.n++
	name := req.GetUsername() + "-" + time.Date(2026, 1, 1, 0, 0, f.backups.n, 0, time.UTC).Format("20060102T150405Z") + ".tar.zst"
	content := append([]byte(strings.Repeat("#", 10)), req.GetAccountJson()...)
	f.backups.files[req.GetUsername()][name] = content
	return &agentv1.BackupCreateResponse{File: name, Size: int64(len(content)), Sha256: "fake"}, nil
}

// BackupRead implements Client.
func (f *Fake) BackupRead(_ context.Context, req *agentv1.BackupReadRequest, _ ...grpc.CallOption) (*agentv1.BackupReadResponse, error) {
	if err := agent.CheckBackupFile(req.GetUsername(), req.GetFile()); err != nil {
		return nil, fakeInvalid(err)
	}
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	c, ok := f.backups.files[req.GetUsername()][req.GetFile()]
	if !ok {
		return nil, fakeNotFound("no such backup")
	}
	off := min(int(req.GetOffset()), len(c))
	end := min(off+int(req.GetLength()), len(c))
	return &agentv1.BackupReadResponse{Data: c[off:end], Size: int64(len(c))}, nil
}

// BackupDelete implements Client.
func (f *Fake) BackupDelete(_ context.Context, req *agentv1.BackupDeleteRequest, _ ...grpc.CallOption) (*agentv1.BackupDeleteResponse, error) {
	f.recordf("BackupDelete %s %s", req.GetUsername(), req.GetFile())
	if err := agent.CheckBackupFile(req.GetUsername(), req.GetFile()); err != nil {
		return nil, fakeInvalid(err)
	}
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	_, ok := f.backups.files[req.GetUsername()][req.GetFile()]
	delete(f.backups.files[req.GetUsername()], req.GetFile())
	return &agentv1.BackupDeleteResponse{Deleted: ok}, nil
}

// BackupRemoveAccount implements Client.
func (f *Fake) BackupRemoveAccount(_ context.Context, req *agentv1.BackupRemoveAccountRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoveAccountResponse, error) {
	f.recordf("BackupRemoveAccount %s", req.GetUsername())
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	_, ok := f.backups.files[req.GetUsername()]
	delete(f.backups.files, req.GetUsername())
	return &agentv1.BackupRemoveAccountResponse{Removed: ok}, nil
}

func fakeNotFound(msg string) error { return status.Error(codes.NotFound, msg) }
