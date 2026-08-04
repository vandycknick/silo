package logfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenAppendRetainsExistingContent(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "netd.log")
	if err := os.WriteFile(path, []byte("before\n"), fileMode); err != nil {
		t.Fatal(err)
	}

	file, err := directory.OpenAppend("netd.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("after\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "before\nafter\n"; got != want {
		t.Fatalf("log content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("log mode = %04o, want %04o", got, fileMode)
	}
}

func TestOpenAppendRejectsUnsafeExistingMode(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "netd.log")
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := directory.OpenAppend("netd.log"); err == nil {
		t.Fatal("expected unsafe existing mode to be rejected")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("unsafe mode was modified to %04o", got)
	}
}

func TestOpenAppendSetsExactModeDespiteUmask(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "netd.log")
	previous := unix.Umask(0o777)
	t.Cleanup(func() { unix.Umask(previous) })
	file, err := directory.OpenAppend("netd.log")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("log mode = %04o, want %04o", got, fileMode)
	}
}

func TestOpenTruncateSetsExactModeWithPermissiveUmask(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "capture.pcap")
	previous := unix.Umask(0)
	t.Cleanup(func() { unix.Umask(previous) })
	file, err := directory.OpenTruncate("capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if err := SyncClose(file); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("capture mode = %04o, want %04o", got, fileMode)
	}
}

func TestOpenTruncateReplacesExistingContent(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "capture.pcap")
	if err := os.WriteFile(path, []byte("stale capture"), fileMode); err != nil {
		t.Fatal(err)
	}

	file, err := directory.OpenTruncate("capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("fresh capture"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := SyncClose(file); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "fresh capture"; got != want {
		t.Fatalf("capture content = %q, want %q", got, want)
	}
}

func TestOpenTruncateRejectsSymlink(t *testing.T) {
	directory, root := testDirectory(t)
	target := filepath.Join(root, "target.pcap")
	path := filepath.Join(root, "capture.pcap")
	if err := os.WriteFile(target, []byte("target"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := directory.OpenTruncate("capture.pcap"); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "target" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestOpenTruncateRejectsNonRegularFile(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.OpenTruncate("directory"); err == nil {
		t.Fatal("expected directory to be rejected")
	}
}

func TestSyncClosePersistsAndClosesFile(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "capture.pcap")
	file, err := directory.OpenTruncate("capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("pcap data"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := SyncClose(file); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err == nil {
		t.Fatal("expected file to be closed")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "pcap data"; got != want {
		t.Fatalf("capture content = %q, want %q", got, want)
	}
}

func TestOpenAppendRejectsSymlink(t *testing.T) {
	directory, root := testDirectory(t)
	target := filepath.Join(root, "target.log")
	path := filepath.Join(root, "netd.log")
	if err := os.WriteFile(target, []byte("target"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := directory.OpenAppend("netd.log"); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "target" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestOpenAppendRejectsNonRegularFile(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.OpenAppend("directory"); err == nil {
		t.Fatal("expected directory to be rejected")
	}
}

func TestWriteReplacesPrivateFileWithoutChangingItsMode(t *testing.T) {
	directory, root := testDirectory(t)
	path := filepath.Join(root, "netd.pid")
	if err := directory.Write("netd.pid", []byte("123")); err != nil {
		t.Fatal(err)
	}
	if err := directory.Write("netd.pid", []byte("9")); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "9" {
		t.Fatalf("PID contents = %q, want %q", got, "9")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("PID mode = %04o, want %04o", got, fileMode)
	}
}

func TestOpenDirectoryRejectsUnsafeDescriptors(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(int(file.Fd())); err == nil {
		t.Fatal("expected regular file descriptor to be rejected")
	}
	if err := file.Close(); err == nil {
		t.Fatal("expected rejected descriptor to be closed")
	}

	path := t.TempDir()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(fd); err == nil {
		t.Fatal("expected non-private directory descriptor to be rejected")
	}
}

func TestDirectoryRejectsNonLeafNames(t *testing.T) {
	directory, _ := testDirectory(t)
	for _, name := range []string{"", ".", "..", "nested/file"} {
		if _, err := directory.OpenAppend(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func testDirectory(t *testing.T) (*Directory, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, directoryMode); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := OpenDirectory(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	return directory, path
}
