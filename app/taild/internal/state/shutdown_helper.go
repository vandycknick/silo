package state

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// LockShutdownHelper is independent of the daemon lock and native VM locks.
// Its raw close-on-exec FD has no Go finalizer and is retained to process exit.
// Lease release proves issuance ended, not that remote native mutations settled.
func LockShutdownHelper(home string) (int, error) { return flock(home, "shutdown-helper.lock") }

// Cancellation cannot restore admission while an ExecStop process can still
// issue stops. Callers must additionally drain the admitted daemon after this
// wait, because cancelled RPC waiters can leave accepted mutations running.
func WaitShutdownHelpers(ctx context.Context, home string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := LockShutdownHelper(home)
		if err == nil {
			return unix.Close(fd)
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
