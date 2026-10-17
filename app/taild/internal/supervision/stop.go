// Package supervision handles host shutdown only. Ordinary daemon termination
// releases handles and leaves machine supervisors alive.
package supervision

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	silo "github.com/vandycknick/silo/sdk/go"
)

const stopWorkers = 16

type StopResult struct {
	Issued, Finished, Failed int
	// Drained means local RPC waiters retired, not native mutations settled.
	Drained <-chan struct{}
}

func (r *StopResult) add(o StopResult) {
	r.Issued += o.Issued
	r.Finished += o.Finished
	r.Failed += o.Failed
}

// StopAll bounds inspect/stop concurrency below the server mutation limit.
// Every force operation retains the exact run inspected before graceful stop.
func StopAll(ctx context.Context, manager *control.Client, instance string) (StopResult, error) {
	drained := make(chan struct{})
	result := StopResult{Drained: drained}
	entries, err := manager.Inventory(ctx)
	if err != nil {
		close(drained)
		return result, err
	}
	ids := make(chan string)
	completed := make(chan error, len(entries))
	var workers sync.WaitGroup
	for range min(stopWorkers, len(entries)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range ids {
				completed <- stopManaged(ctx, manager, instance, id)
			}
		}()
	}
	go func() { workers.Wait(); close(drained) }()
	for _, entry := range entries {
		if entry.Data == nil || !runtime.Managed(entry.Data.MachineData, instance) {
			continue
		}
		select {
		case ids <- entry.Data.ID:
			result.Issued++
		case <-ctx.Done():
			close(ids)
			return result, ctx.Err()
		}
	}
	close(ids)
	for result.Finished < result.Issued {
		select {
		case err := <-completed:
			result.Finished++
			if err != nil {
				result.Failed++
			}
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}
	if result.Failed != 0 {
		return result, errors.New("some managed VM stops failed")
	}
	return result, nil
}

func stopManaged(ctx context.Context, manager *control.Client, instance string, id string) error {
	data, err := manager.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if !runtime.Managed(data.MachineData, instance) {
		return errors.New("shutdown ownership changed")
	}
	if data.Status.Kind == silo.MachineStatusStopped {
		return nil
	}
	if data.RunID == nil {
		return errors.New("shutdown running generation unavailable")
	}
	remaining := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	grace := min(remaining, max(time.Millisecond, remaining*2/3))
	_, err = manager.Stop(ctx, id, data.RunID, silo.StopOptions{Timeout: grace})
	if silo.IsErrorKind(err, silo.ErrorMachineNotRunning) {
		return nil
	}
	if err != nil && ctx.Err() == nil {
		forceBudget := remaining / 3
		if deadline, ok := ctx.Deadline(); ok {
			forceBudget = min(forceBudget, time.Until(deadline))
		}
		if forceBudget > 0 {
			_, err = manager.Stop(ctx, id, data.RunID, silo.StopOptions{Force: true, Timeout: forceBudget})
			if silo.IsErrorKind(err, silo.ErrorMachineNotRunning) {
				return nil
			}
		}
	}
	return err
}

// Sweep seals no admission itself: callers must persist the shutdown marker.
// A fresh post-drain pass is mandatory even when the initial inventory is empty.
func Sweep(ctx context.Context, manager *control.Client, instance, generation string) (total StopResult, finalError error) {
	first, firstError := StopAll(ctx, manager, instance)
	total.add(first)
	drains := []<-chan struct{}{first.Drained}
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
	if err := manager.DrainMutations(ctx, generation); err != nil {
		return total, errors.Join(firstError, err)
	}
	if ctx.Err() != nil {
		return total, ctx.Err()
	}
	final, err := StopAll(ctx, manager, instance)
	total.add(final)
	drains = append(drains, final.Drained)
	settled := manager.DrainMutations(ctx, generation)
	return total, errors.Join(firstError, err, settled)
}
