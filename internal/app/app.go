// Package app wires the pieces that several binaries share: config, logger,
// database and auth service (02-tech-stack-and-repo.md: internal/app).
package app

import (
	"context"
	"log/slog"
	"os"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/logging"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

// App holds the opened shared services. Close it when done.
type App struct {
	Cfg   config.Config
	Log   *slog.Logger
	DB    *store.DB
	Auth  *auth.Service
	Audit *audit.Recorder
}

// Open loads the config, opens (and migrates) the database and builds the
// auth service. On a server, call DropPrivileges first when running as root,
// so files the database creates belong to the service user.
func Open(ctx context.Context, configPath string) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	log := logging.New(os.Stderr, cfg.Log.Level, cfg.Log.Format)
	db, err := store.Open(ctx, cfg.DB.Path)
	if err != nil {
		return nil, err
	}
	key, err := secretbox.LoadOrCreateKey(cfg.Paths.MasterKeyFile())
	if err != nil {
		db.Close()
		return nil, err
	}
	box, err := secretbox.New(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	rec := audit.NewRecorder(db)
	svc, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: cfg.API.SessionIdle.Duration,
		SessionMax:  cfg.API.SessionMax.Duration,
		Log:         log,
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &App{Cfg: cfg, Log: log, DB: db, Auth: svc, Audit: rec}, nil
}

// Close releases the database.
func (a *App) Close() error { return a.DB.Close() }
