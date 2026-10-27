//go:build linux

package agentrpc

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// serveUnix runs a Ping-only server on a real Unix socket with kernel peer credentials.
func serveUnix(t *testing.T, allowed uint32) Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(PeerCredentials([]uint32{allowed})),
		grpc.UnaryInterceptor(ServerInterceptor(discardLog(), []uint32{allowed})))
	agentv1.RegisterAgentServiceServer(gs, &Server{Version: "unix", Log: discardLog()})
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)

	c, closer, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closer.Close() })
	return c
}

func TestUnixSocketAllowsOwnUID(t *testing.T) {
	c := serveUnix(t, uint32(os.Getuid()))
	resp, err := c.Ping(ctx, &agentv1.PingRequest{})
	if err != nil || resp.GetVersion() != "unix" {
		t.Fatalf("Ping = %v, %v", resp, err)
	}
}

func TestUnixSocketRefusesOtherUID(t *testing.T) {
	c := serveUnix(t, uint32(os.Getuid())+1)
	_, err := c.Ping(ctx, &agentv1.PingRequest{})
	// The handshake fails, so the client sees the connection as unavailable.
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", code, err)
	}
}
