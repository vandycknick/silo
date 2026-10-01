//go:build linux && cgo && silo_e2e

// Package signaldiagnostic provides read-only kernel signal-action diagnostics
// for the isolated attachment test child. It never installs or repairs handlers.
package signaldiagnostic

/*
#include <signal.h>
#include <stdint.h>
#include <errno.h>

static int silo_query_action(int sig, uint64_t *flags, uintptr_t *handler, uint64_t *mask) {
    struct sigaction action;
    if (sigaction(sig, NULL, &action) != 0) return errno;
    *flags = (unsigned int)action.sa_flags;
    *handler = (uintptr_t)action.sa_sigaction;
    *mask = 0;
    for (int i = 1; i <= 64; i++) {
        if (sigismember(&action.sa_mask, i) == 1) *mask |= (uint64_t)1 << (i - 1);
    }
    return 0;
}
*/
import "C"

import "syscall"

const OnStack = uint64(C.SA_ONSTACK)

type Action struct {
	Flags   uint64
	Handler uintptr
	Mask    uint64
}

func Query(signal syscall.Signal) (Action, error) {
	var flags, mask C.uint64_t
	var handler C.uintptr_t
	if err := C.silo_query_action(C.int(signal), &flags, &handler, &mask); err != 0 {
		return Action{}, syscall.Errno(err)
	}
	return Action{Flags: uint64(flags), Handler: uintptr(handler), Mask: uint64(mask)}, nil
}
