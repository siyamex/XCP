// Package app wires the pieces that several binaries share: config, logger,
// database and auth service (02-tech-stack-and-repo.md: internal/app).
package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"
	"os"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/logging"
	"github.com/siyamex/XCP/internal/plans"
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
	Plans *plans.Service
	// DomainKey signs domain verification tokens (derived from the master key).
	DomainKey []byte
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
	return &App{
		Cfg: cfg, Log: log, DB: db, Auth: svc, Audit: rec, Plans: plans.NewService(db, rec),
		DomainKey: deriveKey(key, "domain-verification"),
	}, nil
}

// deriveKey returns a subkey of the master key for one purpose, so the
// master key itself is used only by secretbox.
func deriveKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("xcp subkey\x00" + purpose))
	return m.Sum(nil)
}

// Close releases the database.
func (a *App) Close() error { return a.DB.Close() }
