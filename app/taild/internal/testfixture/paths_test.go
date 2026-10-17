package testfixture

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestShortTempDir(t *testing.T) {
	var dir string
	t.Run("private_root", func(t *testing.T) {
		dir = ShortTempDir(t)
		parent := "/tmp"
		if runtime.GOOS == "darwin" {
			parent = "/private/tmp"
		}
		if !filepath.IsAbs(dir) || filepath.Dir(dir) != parent {
			t.Fatalf("unexpected run root: %q", dir)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("run root must be a mode-0700 directory: %v", info.Mode())
		}
		if socket := filepath.Join(dir, "machines", "00000000-0000-0000-0000-000000000000", "vsock.sock"); len(socket) >= 100 {
			t.Fatalf("run root exceeds socket path budget: %q", socket)
		}
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("run root survived cleanup: %v", err)
	}
}
