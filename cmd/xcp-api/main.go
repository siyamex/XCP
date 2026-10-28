// Command xcp-api serves the XCP REST API and the web UI. It runs as
// the unprivileged "xcp" user and reaches root only through xcp-agent
// (01-architecture.md §1). Admin tasks live in xcpctl.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/app"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/httpapi"
	"github.com/siyamex/XCP/internal/version"
	"github.com/siyamex/XCP/web"
)

func main() {
	if err := serve(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xcp-api:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("xcp-api", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to xcp.toml")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.Open(ctx, *configPath)
	if err != nil {
		return err
	}
	defer a.Close()

	if a.Cfg.API.InsecureDevHTTP {
		if err := requireLoopback(a.Cfg.API.Listen); err != nil {
			return err
		}
		a.Log.Warn("serving plain HTTP (api.insecure_dev_http): development only")
	}
	agent, closer, err := agentrpc.Connect(a.Cfg.Agent)
	if err != nil {
		return err
	}
	defer closer.Close()
	if a.Cfg.Agent.Fake {
		a.Log.Warn("using the in-memory fake agent (agent.fake): nothing is changed on this system")
	}
	if err := a.Plans.EnsureDefaults(ctx); err != nil {
		return fmt.Errorf("create default package: %w", err)
	}
	if n, err := a.DB.CountLogins(ctx); err == nil && n == 0 {
		a.Log.Warn("no logins yet; create the first admin with: xcpctl admin create --username admin")
	}

	handler := httpapi.New(httpapi.Deps{
		Auth: a.Auth, Plans: a.Plans, Agent: agent, Log: a.Log,
		SecureCookies: !a.Cfg.API.InsecureDevHTTP,
		UI:            web.Dist(),
	})
	srv := &http.Server{
		Addr:              a.Cfg.API.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go purgeSessions(ctx, a)

	errc := make(chan error, 1)
	go func() {
		a.Log.Info("xcp-api listening", "addr", a.Cfg.API.Listen, "version", version.Version, "tls", !a.Cfg.API.InsecureDevHTTP)
		if a.Cfg.API.InsecureDevHTTP {
			errc <- srv.ListenAndServe()
		} else {
			errc <- srv.ListenAndServeTLS(a.Cfg.API.TLSCert, a.Cfg.API.TLSKey)
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	a.Log.Info("xcp-api shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// requireLoopback stops plain-HTTP dev mode from ever listening on a public address.
func requireLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("api.insecure_dev_http requires a loopback api.listen address (like 127.0.0.1:2443), got %q", listen)
	}
	return nil
}

func purgeSessions(ctx context.Context, a *app.App) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		if n, err := a.DB.DeleteExpiredSessions(ctx, time.Now()); err != nil && ctx.Err() == nil {
			a.Log.Warn("purge expired sessions", "err", err)
		} else if n > 0 {
			a.Log.Info("purged expired sessions", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
