package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/state"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

func defaultShutdownProtection() daemonv1.ShutdownProtection {
	return daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNSUPPORTED
}

func startShutdownProtection(_ context.Context, _ config.Config, _ *control.Client, _, _ string, _ *state.ShutdownGate, _ *jobs.Registry, _ *slog.Logger) (daemonv1.ShutdownProtection, func(), error) {
	// No fabricated host state, inhibitor, DBus, systemctl, or marker recovery.
	return defaultShutdownProtection(), func() {}, nil
}

func runShutdownOnly(context.Context, config.Config, *control.Client, string) error {
	return errors.New("host shutdown protection unsupported on Darwin")
}
