//go:build silo_e2e

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func TestGoSDKCreatesMachineFromLocalDisk(t *testing.T) {
	runtimeRoot := os.Getenv("SILO_TEST_RUNTIME_ROOT")
	disk := os.Getenv("SILO_TEST_DISK_IMAGE")
	if runtimeRoot == "" {
		t.Fatal("SILO_TEST_RUNTIME_ROOT is required")
	}
	if disk == "" {
		t.Skip("SILO_TEST_DISK_IMAGE is not available on this qualification host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runtime, err := silo.Open(ctx, silo.WithDataRoot(t.TempDir()), silo.WithRuntimeRoot(runtimeRoot))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	machine, err := runtime.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("go-sdk-disk-e2e"), silo.WithMemory(silo.Gibibytes(1)), silo.WithoutGuestAgent())
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = machine.Stop(cleanupCtx)
		_ = machine.Remove(cleanupCtx)
	}()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if data.RootFS == nil || data.RootFS.SourceKind != "disk" {
		t.Fatalf("unexpected rootfs: %#v", data.RootFS)
	}
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(5 * time.Second):
	}
	data, err = machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if data.Status.Kind != silo.MachineStatusRunning {
		t.Fatalf("disk machine status = %#v, want running", data.Status)
	}
	if _, err = machine.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err = machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
