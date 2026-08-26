package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func main() {
	runtimeRoot := flag.String("runtime-root", os.Getenv("SILO_EXAMPLE_RUNTIME_ROOT"), "use an existing staged runtime instead of installing a release runtime")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, *runtimeRoot); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, runtimeRoot string) error {
	if runtimeRoot == "" {
		installation, err := silo.InstallRuntime(ctx)
		if err != nil {
			return err
		}
		runtimeRoot = installation.Root
	}

	runtime, err := silo.Open(ctx, silo.WithRuntimeRoot(runtimeRoot))
	if err != nil {
		return err
	}
	defer runtime.Close()

	machine, err := runtime.CreateMachine(ctx, silo.OCIImage("ubuntu:24.04"), silo.WithName("go-example"), silo.WithCPUs(2), silo.WithMemory(silo.Gibibytes(2)))
	if err != nil {
		return err
	}
	defer machine.Close()
	removed := false
	defer func() {
		if removed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = machine.Stop(cleanupCtx)
		_ = machine.Remove(cleanupCtx)
	}()

	if _, err = machine.Start(ctx); err != nil {
		return err
	}
	if err = waitForReady(ctx, machine); err != nil {
		return err
	}
	output, err := machine.Exec(ctx, "/usr/bin/uname", []string{"-a"})
	if err != nil {
		return err
	}
	fmt.Print(output.Stdout())
	if _, err = machine.Stop(ctx); err != nil {
		return err
	}
	if err = machine.Remove(ctx); err != nil {
		return err
	}
	removed = true
	return nil
}

func waitForReady(ctx context.Context, machine *silo.Machine) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := machine.Inspect(ctx)
		if err != nil {
			return err
		}
		if data.Status.Ready != nil && *data.Status.Ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
