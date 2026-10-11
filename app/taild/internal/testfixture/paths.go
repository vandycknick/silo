package testfixture

import (
	"os"
	"runtime"
	"testing"
)

// ShortTempDir creates a private run root within the Unix socket path budget.
func ShortTempDir(t testing.TB) string {
	t.Helper()
	parent := "/tmp"
	if runtime.GOOS == "darwin" {
		parent = "/private/tmp"
	}
	dir, err := os.MkdirTemp(parent, "silo-t-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
