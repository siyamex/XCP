//go:build !linux

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/siyamex/XCP/internal/config"
)

func serve(context.Context, config.Config, *slog.Logger) error {
	return errors.New("xcp-agent runs only on Linux; for development set agent.fake = true and run xcp-api")
}
