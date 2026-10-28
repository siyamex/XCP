package agentrpc

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/fsx"
)

// Server exposes the agent operations over gRPC.
type Server struct {
	agentv1.UnimplementedAgentServiceServer

	Services agent.Services
	Files    *agent.Files
	Accounts *agent.Accounts
	Web      *agent.Web
	Version  string
	Hostname string
	Log      *slog.Logger
}

// Ping implements agentv1.AgentServiceServer.
func (s *Server) Ping(context.Context, *agentv1.PingRequest) (*agentv1.PingResponse, error) {
	return &agentv1.PingResponse{Version: s.Version, Hostname: s.Hostname}, nil
}

// ServiceStatus implements agentv1.AgentServiceServer.
func (s *Server) ServiceStatus(ctx context.Context, req *agentv1.ServiceStatusRequest) (*agentv1.ServiceStatusResponse, error) {
	unit, st, err := s.Services.Status(ctx, req.GetService())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.ServiceStatusResponse{
		Service:     req.GetService(),
		Unit:        unit,
		ActiveState: st.ActiveState,
		SubState:    st.SubState,
		MainPid:     st.MainPID,
		Enabled:     st.Enabled,
	}, nil
}

var actions = map[agentv1.ServiceActionKind]agent.Action{
	agentv1.ServiceActionKind_SERVICE_ACTION_KIND_START:   agent.ActionStart,
	agentv1.ServiceActionKind_SERVICE_ACTION_KIND_STOP:    agent.ActionStop,
	agentv1.ServiceActionKind_SERVICE_ACTION_KIND_RESTART: agent.ActionRestart,
	agentv1.ServiceActionKind_SERVICE_ACTION_KIND_RELOAD:  agent.ActionReload,
}

// ServiceAction implements agentv1.AgentServiceServer.
func (s *Server) ServiceAction(ctx context.Context, req *agentv1.ServiceActionRequest) (*agentv1.ServiceActionResponse, error) {
	a, ok := actions[req.GetAction()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown action %v", req.GetAction())
	}
	if err := s.Services.Do(ctx, req.GetService(), a); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.ServiceActionResponse{}, nil
}

var validators = map[agentv1.Validator]agent.Validator{
	agentv1.Validator_VALIDATOR_UNSPECIFIED: agent.ValidatorNone,
	agentv1.Validator_VALIDATOR_APACHE:      agent.ValidatorApache,
	agentv1.Validator_VALIDATOR_NGINX:       agent.ValidatorNginx,
	agentv1.Validator_VALIDATOR_POSTFIX:     agent.ValidatorPostfix,
}

// FileWriteManaged implements agentv1.AgentServiceServer.
func (s *Server) FileWriteManaged(ctx context.Context, req *agentv1.FileWriteManagedRequest) (*agentv1.FileWriteManagedResponse, error) {
	v, ok := validators[req.GetValidator()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown validator %v", req.GetValidator())
	}
	// Raw Unix mode bits; agent.Files accepts only 0600/0640/0644.
	changed, err := s.Files.Write(ctx, req.GetPath(), req.GetContent(), fs.FileMode(req.GetMode()), v)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FileWriteManagedResponse{Changed: changed}, nil
}

// FileRemoveManaged implements agentv1.AgentServiceServer.
func (s *Server) FileRemoveManaged(ctx context.Context, req *agentv1.FileRemoveManagedRequest) (*agentv1.FileRemoveManagedResponse, error) {
	v, ok := validators[req.GetValidator()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown validator %v", req.GetValidator())
	}
	changed, err := s.Files.Remove(ctx, req.GetPath(), v)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.FileRemoveManagedResponse{Changed: changed}, nil
}

// toStatus maps agent errors to gRPC codes so callers can react without
// parsing messages.
func (s *Server) toStatus(err error) error {
	var vf *agent.ValidationFailedError
	switch {
	case errors.Is(err, agent.ErrInvalidRequest):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, agent.ErrNotOurUser):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, agent.ErrNotInstalled):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &vf):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, fsx.ErrSymlink), errors.Is(err, fsx.ErrEscape):
		// Something replaced part of a managed tree with a symlink: worth an alert.
		s.Log.Error("refused managed path containing a symlink", "err", err)
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	}
	s.Log.Error("agent operation failed", "err", err)
	return status.Error(codes.Internal, err.Error())
}
