package sshdoor

import (
	"os"
	"path/filepath"
	"testing"
)

// muxSocketPath returns a Unix socket path that stays within sun_path even when
// TMPDIR is nested and the subtest name is long; t.TempDir() embeds both.
func muxSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mux-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "mux")
}
