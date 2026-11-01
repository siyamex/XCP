// Command xcp-userd does file work for one account as the account's user
// (ADR-0009). systemd starts it from xcp-userd@<user>.socket on the first
// connection, passing the listening socket; it serves xcp-api there and
// exits after a while without requests.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/siyamex/XCP/internal/userfs"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-userd:", err)
		os.Exit(1)
	}
}

// listener returns the socket systemd passed (socket activation).
func listener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, errors.New("not started by systemd socket activation (LISTEN_PID)")
	}
	if n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS")); n != 1 {
		return nil, fmt.Errorf("want one socket from systemd, got LISTEN_FDS=%q", os.Getenv("LISTEN_FDS"))
	}
	f := os.NewFile(3, "systemd-socket")
	defer f.Close()
	return net.FileListener(f)
}

func run() error {
	home := flag.String("home", "", "the account's home folder")
	idle := flag.Duration("idle", 10*time.Minute, "exit after this long without requests")
	flag.Parse()
	if *home == "" {
		return errors.New("--home is required")
	}
	if os.Geteuid() == 0 {
		return errors.New("must not run as root: it runs as the account's user")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lis, err := listener()
	if err != nil {
		return err
	}
	fsys, err := userfs.Open(*home)
	if err != nil {
		return err
	}
	defer fsys.Close()

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	srv := &http.Server{
		Handler:           userfs.Handler(fsys, touch),
		ReadHeaderTimeout: 10 * time.Second,
		ConnState:         func(net.Conn, http.ConnState) { touch() }, // long uploads keep it alive
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > *idle {
					log.Info("idle, exiting")
					stop()
					return
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
