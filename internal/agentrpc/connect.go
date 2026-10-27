package agentrpc

import (
	"io"

	"github.com/siyamex/XCP/internal/config"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Connect returns the agent client xcp-api and xcp-worker should use: the
// in-memory Fake when agent.fake is set (development), otherwise a client
// for the agent socket.
func Connect(cfg config.Agent) (Client, io.Closer, error) {
	if cfg.Fake {
		return NewFake(), nopCloser{}, nil
	}
	return Dial(cfg.Socket)
}
