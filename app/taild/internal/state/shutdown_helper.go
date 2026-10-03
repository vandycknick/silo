package state

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// LockShutdownHelper is independent of the daemon lock and native VM locks.
// Its raw close-on-exec FD has no Go finalizer. The helper deliberately keeps
// it until process exit, when every in-process native stop thread is gone.
func LockShutdownHelper(home string) (int, error) { return flock(home, "shutdown-helper.lock") }

// Cancellation cannot restore admission while an ExecStop process can still
// issue stops. No daemon-exclusive lock is involved in this wait.
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
