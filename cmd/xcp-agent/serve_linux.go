//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/version"
)

func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	apiUID, apiGID, err := lookupUser(cfg.Agent.APIUser)
	if err != nil {
		return err
	}

	allowed := []string{agent.SystemctlPath}
	for _, c := range agent.ValidatorCommands {
		allowed = append(allowed, c.Path)
	}
	runner, err := execx.NewRunner(allowed...)
	if err != nil {
		return err
	}

	dirs := cfg.Agent.ManagedDirs
	if len(dirs) == 0 {
		dirs = agent.DefaultManagedDirs
	}
	for _, d := range dirs {
		// Services (Apache, nginx) must read generated configs, so these stay world-readable.
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: see above
			return fmt.Errorf("create managed dir: %w", err)
		}
	}
	files, err := agent.NewFiles(dirs, agent.ExecConfigCheck(runner))
	if err != nil {
		return err
	}

	lis, err := listenSocket(cfg.Agent.Socket, apiGID)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	allowedUIDs := []uint32{0, apiUID}
	gs := grpc.NewServer(
		grpc.Creds(agentrpc.PeerCredentials(allowedUIDs)),
		grpc.UnaryInterceptor(agentrpc.ServerInterceptor(log, allowedUIDs)),
	)
	agentv1.RegisterAgentServiceServer(gs, &agentrpc.Server{
		Services: agent.Services{
			Registry: agent.NewServiceRegistry(agent.UbuntuServices()),
			Manager:  agent.Systemctl{Run: runner},
		},
		Files:    files,
		Version:  version.Version,
		Hostname: hostname,
		Log:      log,
	})

	errc := make(chan error, 1)
	go func() { errc <- gs.Serve(lis) }()
	log.Info("xcp-agent listening", "socket", cfg.Agent.Socket, "api_user", cfg.Agent.APIUser, "version", version.Version)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("xcp-agent shutting down")
	done := make(chan struct{})
	go func() { gs.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Warn("graceful stop timed out; forcing")
		gs.Stop()
	}
	return nil
}

func lookupUser(name string) (uid, gid uint32, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("agent.api_user %q: %w", name, err)
	}
	uid64, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid64, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err := errors.Join(err1, err2); err != nil {
		return 0, 0, fmt.Errorf("agent.api_user %q: %w", name, err)
	}
	if uid64 == 0 {
		return 0, 0, fmt.Errorf("agent.api_user %q must not be root", name)
	}
	return uint32(uid64), uint32(gid64), nil
}

// listenSocket creates the agent socket: directory 0750 and socket 0660,
// both owned by root with the API user's group. File permissions are the
// first barrier; SO_PEERCRED checks are the second.
func listenSocket(path string, gid uint32) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.Chown(dir, 0, int(gid)); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: directory, group must traverse
		return nil, err
	}
	// Remove a stale socket from a previous run, but never anything else.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(os.Chown(path, 0, int(gid)), os.Chmod(path, 0o660)); err != nil { //nolint:gosec // G302: socket must be group-writable for the API user
		lis.Close()
		return nil, err
	}
	return lis, nil
}
