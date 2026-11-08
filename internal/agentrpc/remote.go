package agentrpc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func remoteSpecFrom(s *agentv1.RemoteSpec) agent.RemoteSpec {
	return agent.RemoteSpec{
		Kind: s.GetKind(), Path: s.GetPath(), Host: s.GetHost(), Port: int(s.GetPort()), User: s.GetUser(), Password: s.GetPassword(),
		PrivateKey: s.GetPrivateKey(), HostKey: s.GetHostKey(), Endpoint: s.GetEndpoint(), Region: s.GetRegion(), Bucket: s.GetBucket(),
		AccessKey: s.GetAccessKey(), SecretKey: s.GetSecretKey(), UseTLS: s.GetUseTls(),
	}
}

// BackupRemoteTest implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoteTest(ctx context.Context, req *agentv1.BackupRemoteTestRequest) (*agentv1.BackupRemoteTestResponse, error) {
	res, err := s.Remote.Test(ctx, remoteSpecFrom(req.GetSpec()))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRemoteTestResponse{HostKey: res.HostKey}, nil
}

// BackupRemoteUpload implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoteUpload(ctx context.Context, req *agentv1.BackupRemoteFileRequest) (*agentv1.BackupRemoteSizeResponse, error) {
	n, err := s.Remote.Upload(ctx, remoteSpecFrom(req.GetSpec()), req.GetUsername(), req.GetFile())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRemoteSizeResponse{Size: n}, nil
}

// BackupRemoteList implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoteList(ctx context.Context, req *agentv1.BackupRemoteListRequest) (*agentv1.BackupRemoteListResponse, error) {
	objs, err := s.Remote.List(ctx, remoteSpecFrom(req.GetSpec()), req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	out := &agentv1.BackupRemoteListResponse{}
	for _, o := range objs {
		out.Objects = append(out.Objects, &agentv1.RemoteObject{Username: o.Account, File: o.File, Size: o.Size, ModifiedUnix: o.Time.Unix()})
	}
	return out, nil
}

// BackupRemoteDelete implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoteDelete(ctx context.Context, req *agentv1.BackupRemoteFileRequest) (*agentv1.BackupRemoteDeleteResponse, error) {
	if err := s.Remote.Delete(ctx, remoteSpecFrom(req.GetSpec()), req.GetUsername(), req.GetFile()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRemoteDeleteResponse{}, nil
}

// BackupRemoteFetch implements agentv1.AgentServiceServer.
func (s *Server) BackupRemoteFetch(ctx context.Context, req *agentv1.BackupRemoteFileRequest) (*agentv1.BackupRemoteSizeResponse, error) {
	n, err := s.Remote.Fetch(ctx, remoteSpecFrom(req.GetSpec()), req.GetUsername(), req.GetFile())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.BackupRemoteSizeResponse{Size: n}, nil
}

// fakeRemote is the fake agent's destinations: one map of files per spec.
type fakeRemote struct {
	mu      sync.Mutex
	dests   map[string]map[string][]byte // destination -> "account/file" -> content
	failing map[string]string            // destination -> error
}

func destKey(s *agentv1.RemoteSpec) string {
	return s.GetKind() + "|" + s.GetHost() + "|" + s.GetBucket() + "|" + s.GetPath()
}

// RemoteFiles returns what a destination holds, for tests (key: account/file).
func (f *Fake) RemoteFiles(spec *agentv1.RemoteSpec) map[string][]byte {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.remote.dests[destKey(spec)] {
		out[k] = v
	}
	return out
}

// PutRemote puts a file at a destination, for tests.
func (f *Fake) PutRemote(spec *agentv1.RemoteSpec, account, file string, data []byte) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	if f.remote.dests == nil {
		f.remote.dests = map[string]map[string][]byte{}
	}
	k := destKey(spec)
	if f.remote.dests[k] == nil {
		f.remote.dests[k] = map[string][]byte{}
	}
	f.remote.dests[k][account+"/"+file] = data
}

// FailRemote makes a destination fail with msg (empty: works again), for tests.
func (f *Fake) FailRemote(spec *agentv1.RemoteSpec, msg string) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	if f.remote.failing == nil {
		f.remote.failing = map[string]string{}
	}
	f.remote.failing[destKey(spec)] = msg
}

func (f *Fake) remoteCheck(spec *agentv1.RemoteSpec) error {
	if err := agent.CheckRemote(remoteSpecFrom(spec)); err != nil {
		return err
	}
	if m := f.remote.failing[destKey(spec)]; m != "" {
		return fmt.Errorf("%s", m)
	}
	return nil
}

// BackupRemoteTest implements Client.
func (f *Fake) BackupRemoteTest(_ context.Context, req *agentv1.BackupRemoteTestRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoteTestResponse, error) {
	f.recordf("BackupRemoteTest %s", destKey(req.GetSpec()))
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	sp := req.GetSpec()
	if sp.GetKind() == agent.RemoteSFTP && sp.GetHostKey() == "" {
		if err := agent.CheckRemote(remoteSpecFrom(sp)); err != nil {
			return nil, err
		}
		return &agentv1.BackupRemoteTestResponse{HostKey: "SHA256:" + strings.Repeat("F", 43)}, nil
	}
	if err := f.remoteCheck(sp); err != nil {
		return nil, err
	}
	return &agentv1.BackupRemoteTestResponse{HostKey: sp.GetHostKey()}, nil
}

// BackupRemoteUpload implements Client.
func (f *Fake) BackupRemoteUpload(_ context.Context, req *agentv1.BackupRemoteFileRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoteSizeResponse, error) {
	f.recordf("BackupRemoteUpload %s %s", req.GetUsername(), req.GetFile())
	if err := agent.CheckBackupFile(req.GetUsername(), req.GetFile()); err != nil {
		return nil, err
	}
	f.backups.mu.Lock()
	data, ok := f.backups.files[req.GetUsername()][req.GetFile()]
	f.backups.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no such backup")
	}
	f.remote.mu.Lock()
	if err := f.remoteCheck(req.GetSpec()); err != nil {
		f.remote.mu.Unlock()
		return nil, err
	}
	f.remote.mu.Unlock()
	f.PutRemote(req.GetSpec(), req.GetUsername(), req.GetFile(), data)
	return &agentv1.BackupRemoteSizeResponse{Size: int64(len(data))}, nil
}

// BackupRemoteList implements Client.
func (f *Fake) BackupRemoteList(_ context.Context, req *agentv1.BackupRemoteListRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoteListResponse, error) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	if err := f.remoteCheck(req.GetSpec()); err != nil {
		return nil, err
	}
	var keys []string
	for k := range f.remote.dests[destKey(req.GetSpec())] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := &agentv1.BackupRemoteListResponse{}
	for _, k := range keys {
		acct, file, _ := strings.Cut(k, "/")
		if req.GetUsername() != "" && req.GetUsername() != acct {
			continue
		}
		out.Objects = append(out.Objects, &agentv1.RemoteObject{Username: acct, File: file, Size: int64(len(f.remote.dests[destKey(req.GetSpec())][k])), ModifiedUnix: time.Now().Unix()})
	}
	return out, nil
}

// BackupRemoteDelete implements Client.
func (f *Fake) BackupRemoteDelete(_ context.Context, req *agentv1.BackupRemoteFileRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoteDeleteResponse, error) {
	f.recordf("BackupRemoteDelete %s %s", req.GetUsername(), req.GetFile())
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	if err := f.remoteCheck(req.GetSpec()); err != nil {
		return nil, err
	}
	delete(f.remote.dests[destKey(req.GetSpec())], req.GetUsername()+"/"+req.GetFile())
	return &agentv1.BackupRemoteDeleteResponse{}, nil
}

// BackupRemoteFetch implements Client.
func (f *Fake) BackupRemoteFetch(_ context.Context, req *agentv1.BackupRemoteFileRequest, _ ...grpc.CallOption) (*agentv1.BackupRemoteSizeResponse, error) {
	f.recordf("BackupRemoteFetch %s %s", req.GetUsername(), req.GetFile())
	if err := agent.CheckBackupFile(req.GetUsername(), req.GetFile()); err != nil {
		return nil, err
	}
	f.remote.mu.Lock()
	if err := f.remoteCheck(req.GetSpec()); err != nil {
		f.remote.mu.Unlock()
		return nil, err
	}
	data, ok := f.remote.dests[destKey(req.GetSpec())][req.GetUsername()+"/"+req.GetFile()]
	f.remote.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("not at the destination")
	}
	f.backups.mu.Lock()
	defer f.backups.mu.Unlock()
	if f.backups.files == nil {
		f.backups.files = map[string]map[string][]byte{}
	}
	if f.backups.files[req.GetUsername()] == nil {
		f.backups.files[req.GetUsername()] = map[string][]byte{}
	}
	if _, exists := f.backups.files[req.GetUsername()][req.GetFile()]; exists {
		return nil, fmt.Errorf("%s is already on this server", req.GetFile())
	}
	f.backups.files[req.GetUsername()][req.GetFile()] = data
	return &agentv1.BackupRemoteSizeResponse{Size: int64(len(data))}, nil
}
