package state

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LockHome prevents two lobby instances from writing one home/node state.
// Machine name coordination with local SDK writers remains the SDK's lock.
func LockHome(home string) (*os.File, error) {
	fd, e := flock(home, "lock")
	if errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN) {
		return nil, errors.New("another taild instance owns this home")
	}
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), "taild lock"), nil
}

// flock takes an exclusive, non-blocking lock on a file inside the private
// taild directory and hands back the raw descriptor that holds it.
func flock(home, name string) (int, error) {
	dir := filepath.Join(home, "taild")
	if e := PrivateDir(dir); e != nil {
		return -1, e
	}
	fd, e := unix.Open(filepath.Join(dir, name), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return -1, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		_ = unix.Close(fd)
		return -1, e
	}
	return fd, nil
}
