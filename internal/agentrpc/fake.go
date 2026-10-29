package agentrpc

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// Fake is an in-memory agent for development and tests (agent.fake = true).
// It applies the same request rules and returns the same gRPC codes as the
// real agent, records every call, and never touches the system.
type Fake struct {
	mu        sync.Mutex
	calls     []string
	files     map[string]fakeFile
	states    map[string]string // unit -> active state
	registry  *agent.ServiceRegistry
	dirs      []string
	failCheck string // non-empty: validated writes fail with this output
	accounts  fakeUsers
	sites     fakeSites
	zones     fakeZones
	hostName  string
	hostCert  string
}

type fakeFile struct {
	content []byte
	mode    uint32
}

var _ Client = (*Fake)(nil)

// NewFake returns a fake agent with Ubuntu service names and the default managed dirs.
func NewFake() *Fake {
	return &Fake{
		files:    map[string]fakeFile{},
		states:   map[string]string{},
		registry: agent.NewServiceRegistry(agent.UbuntuServices()),
		dirs:     slices.Clone(agent.DefaultManagedDirs),
	}
}

// Calls returns the recorded calls, oldest first.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// File returns a written file's content.
func (f *Fake) File(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	return bytes.Clone(file.content), ok
}

// FailValidation makes validated writes and removes fail with output, as
// if the generated config were broken. An empty string turns it off.
func (f *Fake) FailValidation(output string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCheck = output
}

func (f *Fake) record(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

// Ping implements Client.
func (f *Fake) Ping(context.Context, *agentv1.PingRequest, ...grpc.CallOption) (*agentv1.PingResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Ping")
	return &agentv1.PingResponse{Version: "fake", Hostname: "fake-agent"}, nil
}

// ServiceStatus implements Client.
func (f *Fake) ServiceStatus(_ context.Context, req *agentv1.ServiceStatusRequest, _ ...grpc.CallOption) (*agentv1.ServiceStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ServiceStatus %s", req.GetService())
	unit, err := f.registry.Unit(req.GetService())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	state := f.states[unit]
	if state == "" {
		state = "active"
	}
	sub := map[string]string{"active": "running", "inactive": "dead"}[state]
	return &agentv1.ServiceStatusResponse{
		Service: req.GetService(), Unit: unit, ActiveState: state, SubState: sub, Enabled: true,
	}, nil
}

// ServiceAction implements Client.
func (f *Fake) ServiceAction(_ context.Context, req *agentv1.ServiceActionRequest, _ ...grpc.CallOption) (*agentv1.ServiceActionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := actions[req.GetAction()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown action %v", req.GetAction())
	}
	f.record("ServiceAction %s %s", req.GetService(), a)
	unit, err := f.registry.Unit(req.GetService())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if a == agent.ActionStop {
		f.states[unit] = "inactive"
	} else {
		f.states[unit] = "active"
	}
	return &agentv1.ServiceActionResponse{}, nil
}

// FileWriteManaged implements Client.
func (f *Fake) FileWriteManaged(_ context.Context, req *agentv1.FileWriteManagedRequest, _ ...grpc.CallOption) (*agentv1.FileWriteManagedResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("FileWriteManaged %s %d bytes %#o", req.GetPath(), len(req.GetContent()), req.GetMode())
	if err := agent.CheckWriteRequest(f.dirs, req.GetPath(), req.GetContent(), fs.FileMode(req.GetMode())); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, ok := validators[req.GetValidator()]; !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown validator %v", req.GetValidator())
	}
	prev, existed := f.files[req.GetPath()]
	if existed && prev.mode == req.GetMode() && bytes.Equal(prev.content, req.GetContent()) {
		return &agentv1.FileWriteManagedResponse{Changed: false}, nil
	}
	if err := f.check(req.GetValidator()); err != nil {
		return nil, err
	}
	f.files[req.GetPath()] = fakeFile{content: bytes.Clone(req.GetContent()), mode: req.GetMode()}
	return &agentv1.FileWriteManagedResponse{Changed: true}, nil
}

// FileRemoveManaged implements Client.
func (f *Fake) FileRemoveManaged(_ context.Context, req *agentv1.FileRemoveManagedRequest, _ ...grpc.CallOption) (*agentv1.FileRemoveManagedResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("FileRemoveManaged %s", req.GetPath())
	if err := agent.CheckRemoveRequest(f.dirs, req.GetPath()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, ok := validators[req.GetValidator()]; !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown validator %v", req.GetValidator())
	}
	if _, existed := f.files[req.GetPath()]; !existed {
		return &agentv1.FileRemoveManagedResponse{Changed: false}, nil
	}
	if err := f.check(req.GetValidator()); err != nil {
		return nil, err
	}
	delete(f.files, req.GetPath())
	return &agentv1.FileRemoveManagedResponse{Changed: true}, nil
}

func (f *Fake) check(v agentv1.Validator) error {
	if v == agentv1.Validator_VALIDATOR_UNSPECIFIED || f.failCheck == "" {
		return nil
	}
	return status.Error(codes.FailedPrecondition, (&agent.ValidationFailedError{Output: strings.TrimSpace(f.failCheck)}).Error())
}
