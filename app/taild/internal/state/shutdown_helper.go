package state

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// LockShutdownHelper is independent of the daemon lock and native VM locks.
// Its raw close-on-exec FD has no Go finalizer. The helper deliberately keeps
// it until process exit, when every in-process native stop thread is gone.
func LockShutdownHelper(home string) (int, error) {
	dir := filepath.Join(home, "taild")
	if err := PrivateDir(dir); err != nil {
		return -1, err
	}
	fd, err := unix.Open(filepath.Join(dir, "shutdown-helper.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return -1, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

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
