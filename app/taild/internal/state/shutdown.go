package state

import (
	"errors"
	"os"
	"path/filepath"
)

func shutdownPath(home string) string { return filepath.Join(home, "taild", "shutdown") }

// The marker is shared with ExecStop, which must not wait for the daemon lock.
// It survives a crash and is cleared only after observing a non-shutdown host.
func MarkShutdown(home string) error {
	if err := PrivateDir(filepath.Join(home, "taild")); err != nil {
		return err
	}
	return AtomicWrite(shutdownPath(home), []byte("shutdown\n"))
}
func ShutdownPending(home string) bool {
	if home == "" {
		return false
	}
	_, err := os.Lstat(shutdownPath(home))
	return !errors.Is(err, os.ErrNotExist)
}
func ClearShutdown(home string) error {
	err := os.Remove(shutdownPath(home))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return SyncDir(filepath.Dir(shutdownPath(home)))
}
