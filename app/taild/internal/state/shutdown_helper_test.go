package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHelperLeaseIsIndependentAndCancellationWaitsForRelease(t *testing.T) {
	home := t.TempDir()
	daemon, err := LockHome(home)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	fd, err := LockShutdownHelper(home)
	if err != nil {
		t.Fatal("helper waited for daemon-exclusive lock", err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := WaitShutdownHelpers(ctx, home); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("active helper did not hold admission", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := WaitShutdownHelpers(ctx, home); err != nil {
		t.Fatal("released helper prevented recovery", err)
	}
}
