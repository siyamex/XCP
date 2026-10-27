package agentrpc

import (
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// Client is what xcp-api and xcp-worker use to talk to the agent. Both the
// real gRPC client and Fake implement it.
type Client = agentv1.AgentServiceClient

// Dial connects to the agent's Unix socket. The connection is lazy: errors
// show up on the first call. Close the returned io.Closer on shutdown.
func Dial(socketPath string) (Client, io.Closer, error) {
	// local credentials refuse to send anything over a non-local connection.
	cc, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(local.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("agent client: %w", err)
	}
	return agentv1.NewAgentServiceClient(cc), cc, nil
}
