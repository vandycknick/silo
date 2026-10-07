package main

import (
	"context"
	"os"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/supervision"
)

// This checks the actual Linux SystemState guard, not synthetic shutdown events
// and not a reboot qualification. No daemon/native fixture is needed: a safe
// host must return before dereferencing the deliberately absent manager.
func TestActualNonStoppingHostShutdownHelperHasNoSideEffects(t *testing.T) {
	if os.Getenv("SILO_TEST_HOST_STATE") != "1" {
		t.Skip("requires explicit actual host-state admission")
	}
	ctx := context.Background()
	host, err := supervision.SystemState(ctx)
	if err != nil {
		t.Skip("actual host state unavailable", err)
	}
	if host == "stopping" {
		t.Skip("host is actually stopping")
	}
	home := t.TempDir()
	if err := runShutdownOnly(ctx, config.Config{Home: home}, nil, ""); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("ordinary host guard created identity, marker or lease", entries, err)
	}
}
