// Command xcp-agent is the only XCP process that runs as root. It
// serves a fixed set of typed operations on a Unix socket to xcp-api and
// xcp-worker (01-architecture.md §1–3).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", config.DefaultPath, "path to xcp.toml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Agent.Fake {
		return errors.New("agent.fake is set: xcp-api uses its in-process fake agent, so xcp-agent must not run")
	}
	log := logging.New(os.Stderr, cfg.Log.Level, cfg.Log.Format)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, log)
}
