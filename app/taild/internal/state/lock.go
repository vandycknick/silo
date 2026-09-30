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
	dir := filepath.Join(home, "taild")
	if e := PrivateDir(dir); e != nil {
		return nil, e
	}
	fd, e := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "taild lock")
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another taild instance owns this home")
	}
	return f, nil
}
