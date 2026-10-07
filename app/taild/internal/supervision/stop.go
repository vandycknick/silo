// Package supervision handles host shutdown only. Ordinary daemon termination
// releases handles and leaves machine supervisors alive.
package supervision

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	silo "github.com/vandycknick/silo/sdk/go"
)

func SystemState(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	if ctx.Err() != nil {
		return "", errors.New("host shutdown state unknown; no VMs stopped")
	}
	value := strings.TrimSpace(string(out))
	// systemctl deliberately exits nonzero for stopping and degraded.
	switch value {
	case "stopping", "running", "degraded", "starting", "initializing", "maintenance", "offline":
		return value, nil
	default:
		return "", errors.New("host shutdown state unknown; no VMs stopped")
	}
}

type StopResult struct {
	Issued, Finished, Failed int
	Drained                  <-chan struct{}
}

func (r *StopResult) add(o StopResult) {
	r.Issued += o.Issued
	r.Finished += o.Finished
	r.Failed += o.Failed
}

type inventoryResult struct {
	entries []control.InventoryEntry
	err     error
}

// StopAll issues every stop concurrently before waiting. Drained tracks local
// RPC waiters only: cancelled RPCs do not prove daemon mutations have completed.
func StopAll(ctx context.Context, r *runtime.Runtime) (StopResult, error) {
	drained := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() { wg.Done(); go func() { wg.Wait(); close(drained) }() }()
	result := StopResult{Drained: drained}
	entriesDone := make(chan inventoryResult, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries, err := r.Control.Inventory(ctx)
		entriesDone <- inventoryResult{entries, err}
	}()
	var entries []control.InventoryEntry
	select {
	case got := <-entriesDone:
		if got.err != nil {
			return result, errors.New("shutdown inventory unavailable")
		}
		entries = got.entries
	case <-ctx.Done():
		return result, ctx.Err()
	}
	completed := make(chan error, len(entries))
	for _, entry := range entries {
		if entry.Data == nil || !runtime.Managed(entry.Data.MachineData, r.Instance) {
			continue
		}
		id := entry.Data.ID
		result.Issued++
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := r.Control.Inspect(ctx, id)
			if err == nil {
				if !runtime.Managed(data.MachineData, r.Instance) {
					completed <- errors.New("shutdown ownership changed")
					return
				}
				if data.Status.Kind == silo.MachineStatusStopped {
					completed <- nil
					return
				}
				if data.RunID == nil {
					completed <- errors.New("shutdown running generation unavailable")
					return
				}
				remaining := time.Second
				if deadline, ok := ctx.Deadline(); ok {
					remaining = time.Until(deadline)
				}
				grace := max(time.Millisecond, remaining*2/3)
				_, err = r.Control.Stop(ctx, id, data.RunID, silo.StopOptions{Timeout: grace})
				if silo.IsErrorKind(err, silo.ErrorMachineNotRunning) {
					err = nil
				}
				if err != nil && ctx.Err() == nil {
					forceBudget := remaining / 3
					if deadline, ok := ctx.Deadline(); ok {
						forceBudget = min(forceBudget, time.Until(deadline))
					}
					if forceBudget > 0 {
						_, err = r.Control.Stop(ctx, id, data.RunID, silo.StopOptions{Force: true, Timeout: forceBudget})
						if silo.IsErrorKind(err, silo.ErrorMachineNotRunning) {
							err = nil
						}
					}
				}
			}
			completed <- err
		}()
	}
	for result.Finished < result.Issued {
		select {
		case err := <-completed:
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return result, errors.New("shutdown stop waiter cancelled; daemon mutation completion unknown")
			}
			result.Finished++
			if err != nil {
				result.Failed++
			}
		case <-ctx.Done():
			return result, errors.New("shutdown stop deadline reached; daemon mutations may remain in flight")
		}
	}
	if result.Failed != 0 {
		return result, errors.New("some managed VM stops failed")
	}
	return result, nil
}

// Sweep keeps discovering records materialized by pre-seal daemon mutations until
// the helper budget expires. It never takes the daemon's exclusive home lock.
func Sweep(ctx context.Context, r *runtime.Runtime) (total StopResult, finalError error) {
	var lastError error
	var drains []<-chan struct{}
	defer func() {
		done := make(chan struct{})
		total.Drained = done
		go func() {
			for _, drain := range drains {
				<-drain
			}
			close(done)
		}()
	}()
	for {
		result, err := StopAll(ctx, r)
		total.add(result)
		drains = append(drains, result.Drained)
		lastError = err
		if err != nil && (ctx.Err() != nil || result.Finished < result.Issued) {
			return total, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			if errors.Is(ctx.Err(), context.Canceled) {
				return total, ctx.Err()
			}
			return total, lastError
		case <-timer.C:
		}
	}
}
