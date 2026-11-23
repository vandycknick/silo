package wire

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Darwin has no SOCK_CLOEXEC. Holding ForkLock while the descriptors are
// still inheritable keeps a concurrent os/exec fork from copying them, the
// same fallback the standard library uses.
func cloexecSocketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return fds, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return fds, nil
}
