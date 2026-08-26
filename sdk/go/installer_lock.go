package silo

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type installLock struct {
	file *os.File
}

func acquireInstallLock(ctx context.Context, path string) (*installLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, newError(ErrorInstallation, "", "open runtime installation lock: "+err.Error())
	}

	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &installLock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, newError(ErrorInstallation, "", "lock runtime installation: "+err.Error())
		}

		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, contextError(ctx.Err())
		case <-timer.C:
		}
	}
}

func (lock *installLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func contextError(err error) error {
	if err == nil {
		return nil
	}
	result := newError(ErrorCancelled, "", err.Error())
	result.cause = err
	return result
}
