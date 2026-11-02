// Command xcp-ftpauth checks FTP logins for Pure-FTPd (ADR-0010): it
// answers Pure-FTPd's extauth requests on a Unix socket from the FTP
// fragments xcp-agent writes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/ftpauth"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-ftpauth:", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", agent.FTPAuthSocket, "where Pure-FTPd connects (its folder must be private)")
	dir := flag.String("fragments", agent.FTPFragmentDir, "the FTP fragments written by xcp-agent")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := os.Remove(*socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	lis, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		lis.Close()
	}()
	log.Info("xcp-ftpauth listening", "socket", *socket, "fragments", *dir)
	if err := (&ftpauth.Server{Dir: *dir, Log: log}).Serve(ctx, lis); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
