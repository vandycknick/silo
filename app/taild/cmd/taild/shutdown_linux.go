package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/supervision"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

func defaultShutdownProtection() daemonv1.ShutdownProtection {
	return daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNAVAILABLE
}

func startShutdownProtection(ctx context.Context, c config.Config, manager *control.Client, instance, generation string, gate *state.ShutdownGate, registry *jobs.Registry, log *slog.Logger) (daemonv1.ShutdownProtection, func(), error) {
	inhibitor, preparing, err := supervision.Acquire(ctx, c)
	protection := defaultShutdownProtection()
	closeProtection := func() {}
	if err != nil {
		log.Warn("logind shutdown protection unavailable")
	} else {
		closeProtection = inhibitor.Close
		protection = daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_ACTIVE
		inhibitor.Start(ctx, c, manager, instance, generation, preparing, gate,
			func() { registry.InterruptIf(func() bool { return true }) }, registry.Resume, registry.Drained, log)
	}
	if !preparing {
		if err := recoverShutdownSeal(ctx, c.Home, gate, manager, generation); err != nil {
			closeProtection()
			return protection, func() {}, err
		}
	}
	// Poll only after startup recovery and ordered event intake are established.
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				registry.InterruptIf(func() bool { return state.ShutdownPending(c.Home) })
			}
		}
	}()
	return protection, closeProtection, nil
}

func recoverShutdownSeal(ctx context.Context, home string, gate *state.ShutdownGate, manager *control.Client, generation string) error {
	revision := gate.Revision()
	if gate.Pending() || !state.ShutdownPending(home) {
		return nil
	}
	if err := state.WaitShutdownHelpers(ctx, home); err != nil {
		return errors.New("shutdown helper still active; admission sealed")
	}
	if err := manager.DrainMutations(ctx, generation); err != nil {
		return errors.New("daemon mutations unsettled; admission sealed")
	}
	if gate.Revision() != revision || gate.Pending() {
		return nil
	}
	host, err := supervision.SystemState(ctx)
	if err != nil || host == "stopping" {
		return errors.New("shutdown marker retained; host state not safe for admission")
	}
	_, err = gate.Recover(home, revision)
	return err
}

func runShutdownOnly(ctx context.Context, c config.Config, manager *control.Client, generation string) error {
	host, err := supervision.SystemState(ctx)
	if err != nil {
		return err
	}
	if host != "stopping" {
		return nil
	}
	instance, err := state.ReadInstance(c.Home)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Raw lease descriptor is deliberately retained to process exit. A cancelled
	// RPC waiter does not prove that accepted native work has settled.
	if _, err = state.LockShutdownHelper(c.Home); err != nil {
		return err
	}
	host, err = supervision.SystemState(ctx)
	if err != nil {
		return err
	}
	if host != "stopping" {
		return nil
	}
	if err = state.MarkShutdown(c.Home); err != nil {
		return err
	}
	stopping, cancel := context.WithTimeout(ctx, c.Shutdown.StopBudget.Duration)
	defer cancel()
	result, err := supervision.Sweep(stopping, manager, instance, generation)
	// Settlement has its own bounded context, independent of owner EOF/episode
	// cancellation. Marker and lease remain held even when that bound expires.
	settling, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	select {
	case <-result.Drained:
	case <-settling.Done():
		return errors.Join(err, settling.Err())
	}
	return errors.Join(err, manager.DrainMutations(settling, generation))
}
