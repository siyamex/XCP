// Command xcp-mailpolicy is the Postfix policy service that limits how much
// mail an account may send per hour (ADR-0028). It runs as the panel's
// service user, reads the panel database and answers Postfix on a Unix socket
// that only the postfix group can reach.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/mailpolicy"
	"github.com/siyamex/XCP/internal/store"
)

// Socket is where Postfix connects.
const Socket = "/run/xcp-mailpolicy/policy.sock"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-mailpolicy:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/xcp/xcp.toml", "configuration file")
	socket := flag.String("socket", Socket, "Unix socket for Postfix")
	flag.Parse()
	if os.Geteuid() == 0 {
		return errors.New("must not run as root: it runs as the panel's service user")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var db *store.DB
	for {
		if db, err = store.OpenMigrated(ctx, cfg.DB.Path); !errors.Is(err, store.ErrNotMigrated) {
			break
		}
		log.Info("waiting for xcp-api to update the database", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		return err
	}
	defer db.Close()

	_ = os.Remove(*socket)
	// The folder belongs to the service; Postfix must be able to enter it.
	if g, err := user.LookupGroup("postfix"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(filepath.Dir(*socket), -1, gid)
		}
	}
	l, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	// Postfix's smtpd runs as postfix: its group may connect, nobody else.
	if g, err := user.LookupGroup("postfix"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(*socket, -1, gid)
		}
	}
	if err := os.Chmod(*socket, 0o660); err != nil { //nolint:gosec // G302: a socket for the postfix group
		return err
	}
	srv := &mailpolicy.Server{
		Decider: &mailpolicy.DBDecider{DB: db}, Limiter: mailpolicy.NewLimiter(), Now: time.Now,
		Log: func(msg string, args ...any) { log.Warn(msg, args...) },
	}
	log.Info("listening", "socket", *socket)
	if err := srv.Serve(ctx, l); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
