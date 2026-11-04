// Command xcp-logd counts bandwidth per domain from the web, FTP and mail
// logs (ADR-0012). It runs as the panel's service user with the adm and
// systemd-journal groups, reads the logs once a minute and adds the bytes
// to the panel database.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/logd"
	"github.com/siyamex/XCP/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-logd:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/xcp/xcp.toml", "configuration file")
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
	// xcp-api migrates the database; wait until it has.
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
	in := &logd.Ingester{DB: db, WebLogs: logd.WebLogs, FTPLog: logd.FTPLog, Unit: logd.MailUnit, Log: log, Queue: jobs.NewQueue(db), Audit: audit.NewRecorder(db)}
	if _, err := os.Stat(logd.JournalctlPath); err == nil {
		if in.Run, err = execx.NewRunner(logd.JournalctlPath); err != nil {
			return err
		}
	}
	log.Info("xcp-logd counting", "web", in.WebLogs, "ftp", in.FTPLog, "mail", in.Run != nil)
	in.Loop(ctx)
	return nil
}
