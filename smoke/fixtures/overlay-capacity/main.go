// Public SDK consumer for byte-exact stopped-machine growth smoke gates.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
)

func run(ctx context.Context, reference, quantity string) error {
	capacity, err := strconv.ParseUint(quantity, 10, 64)
	if err != nil {
		return fmt.Errorf("exact capacity: %w", err)
	}
	home, root := os.Getenv("SILO_HOME"), os.Getenv("SILO_RUNTIME_DIR")
	if home == "" || root == "" {
		return fmt.Errorf("private SILO_HOME and staged SILO_RUNTIME_DIR are required")
	}
	runtime, err := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(root))
	if err != nil {
		return err
	}
	defer runtime.Close()
	machine, err := runtime.Machine(ctx, reference)
	if err != nil {
		return err
	}
	defer machine.Close()
	size := silo.Bytes(capacity)
	data, err := machine.Update(ctx, silo.MachineUpdate{RootDiskSize: &size})
	if err != nil {
		return err
	}
	if data.RootDiskSize == nil || data.RootDiskSize.Bytes() != capacity {
		return fmt.Errorf("stopped update did not return the exact published capacity")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		CapacityBytes uint64 `json:"capacityBytes"`
	}{CapacityBytes: data.RootDiskSize.Bytes()})
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: overlay-capacity MACHINE EXACT_BYTES")
		os.Exit(2)
	}
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(signals, 240*time.Second)
	err := run(ctx, os.Args[1], os.Args[2])
	cancel()
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
