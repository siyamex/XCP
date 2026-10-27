// Package agentrpc is the gRPC transport between xcp-api/xcp-worker and
// xcp-agent: Unix socket, peer-credential checks, client, server, and a fake
// agent for development (01-architecture.md §1–3).
package agentrpc

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc/codes"
)

// PeerCreds identifies the process on the other end of the Unix socket,
// as reported by the kernel (SO_PEERCRED), not by the client.
type PeerCreds struct {
	credentials.CommonAuthInfo
	UID uint32
	GID uint32
	PID int32
}

// AuthType implements credentials.AuthInfo.
func (PeerCreds) AuthType() string { return "peercred" }

func newPeerCreds(uid, gid uint32, pid int32) PeerCreds {
	return PeerCreds{
		// A Unix socket never leaves the machine.
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		UID:            uid, GID: gid, PID: pid,
	}
}

// ServerInterceptor checks on every call that the peer's UID is allowed
// (the handshake already checked it; this is defence in depth), and logs
// each call with the caller's UID and PID.
func ServerInterceptor(log *slog.Logger, allowedUIDs []uint32) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "no peer information")
		}
		pc, ok := p.AuthInfo.(PeerCreds)
		if !ok || !slices.Contains(allowedUIDs, pc.UID) {
			log.Warn("agent call refused", "method", info.FullMethod, "peer", fmt.Sprintf("%v", p.AuthInfo))
			return nil, status.Error(codes.PermissionDenied, "caller not allowed")
		}
		start := time.Now()
		resp, err := handler(ctx, req)
		log.Info("agent call",
			"method", info.FullMethod, "uid", pc.UID, "pid", pc.PID,
			"code", status.Code(err).String(), "duration", time.Since(start))
		return resp, err
	}
}
