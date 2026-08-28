package silo

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type testArchiveEntry struct {
	name     string
	mode     int64
	typeflag byte
	body     []byte
	linkname string
}

func TestCurrentRuntimeTarget(t *testing.T) {
	t.Parallel()

	cases := []struct {
		goos, goarch string
		want         RuntimeTarget
		wantError    bool
	}{
		{goos: "darwin", goarch: "arm64", want: RuntimeTargetDarwinARM64},
		{goos: "linux", goarch: "amd64", want: RuntimeTargetLinuxAMD64GNU},
		{goos: "linux", goarch: "arm64", want: RuntimeTargetLinuxARM64GNU},
		{goos: "windows", goarch: "amd64", wantError: true},
		{goos: "darwin", goarch: "amd64", wantError: true},
	}
	for _, test := range cases {
		t.Run(test.goos+"/"+test.goarch, func(t *testing.T) {
			t.Parallel()
			got, err := currentRuntimeTarget(test.goos, test.goarch)
			if test.wantError {
				if !IsErrorKind(err, ErrorUnsupportedTarget) {
					t.Fatalf("error = %v, want ErrorUnsupportedTarget", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("currentRuntimeTarget() failed: %v", err)
			}
			if got != test.want {
				t.Fatalf("target = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallRuntimeFromVerifiedArchive(t *testing.T) {
	t.Parallel()

	metadata, archive := createRuntimeArchive(t, nil)
	installRoot := t.TempDir()
	installation, err := installRuntime(context.Background(), metadata.target, installConfig{
		installRoot: installRoot,
		archivePath: archive,
		metadata:    metadata,
	})
	if err != nil {
		t.Fatalf("installRuntime() failed: %v", err)
	}
	wantRoot := filepath.Join(installRoot, Version, string(metadata.target))
	if installation.Root != wantRoot {
		t.Fatalf("Root = %q, want %q", installation.Root, wantRoot)
	}
	for relative, mode := range runtimeFiles {
		info, statErr := os.Stat(filepath.Join(wantRoot, filepath.FromSlash(relative)))
		if statErr != nil {
			t.Fatalf("stat %s: %v", relative, statErr)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("mode for %s = %04o, want %04o", relative, info.Mode().Perm(), mode)
		}
	}

	// A complete installation is reused even after the source archive disappears.
	if err := os.Remove(archive); err != nil {
		t.Fatalf("remove source archive: %v", err)
	}
	again, err := installRuntime(context.Background(), metadata.target, installConfig{
		installRoot: installRoot,
		archivePath: archive,
		metadata:    metadata,
	})
	if err != nil {
		t.Fatalf("reuse installRuntime() failed: %v", err)
	}
	if again.Root != installation.Root {
		t.Fatalf("reused Root = %q, want %q", again.Root, installation.Root)
	}
}

func TestInstallRuntimeCoordinatesConcurrentInstallers(t *testing.T) {
	t.Parallel()

	metadata, archive := createRuntimeArchive(t, nil)
	root := t.TempDir()
	type result struct {
		installation *RuntimeInstallation
		err          error
	}
	results := make(chan result, 6)
	for range 6 {
		go func() {
			installation, err := installRuntime(context.Background(), metadata.target, installConfig{installRoot: root, archivePath: archive, metadata: metadata})
			results <- result{installation: installation, err: err}
		}()
	}
	var expected string
	for range 6 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent install failed: %v", result.err)
		}
		if expected == "" {
			expected = result.installation.Root
		}
		if result.installation.Root != expected {
			t.Fatalf("Root = %q, want %q", result.installation.Root, expected)
		}
	}
}

func TestInstallRuntimeDownloadsFromMirror(t *testing.T) {
	t.Parallel()
	metadata, archive := createRuntimeArchive(t, nil)
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		want := "/v" + Version + "/" + metadata.name
		if request.URL.Path != want {
			t.Errorf("request path = %q, want %q", request.URL.Path, want)
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(contents)
	}))
	defer server.Close()
	installation, err := installRuntime(context.Background(), metadata.target, installConfig{installRoot: t.TempDir(), mirrorURL: server.URL, metadata: metadata})
	if err != nil {
		t.Fatalf("installRuntime() failed: %v", err)
	}
	if installation == nil {
		t.Fatal("installation is nil")
	}
}

func TestInstallRuntimeRejectsDigestMismatch(t *testing.T) {
	t.Parallel()

	metadata, archive := createRuntimeArchive(t, nil)
	metadata.sha256 = string(bytes.Repeat([]byte{'0'}, sha256.Size*2))
	_, err := installRuntime(context.Background(), metadata.target, installConfig{
		installRoot: t.TempDir(),
		archivePath: archive,
		metadata:    metadata,
	})
	if !IsErrorKind(err, ErrorArchiveIntegrity) {
		t.Fatalf("error = %v, want ErrorArchiveIntegrity", err)
	}
}

func TestInstallRuntimeRejectsUnsafeArchives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		change func(string, []testArchiveEntry) []testArchiveEntry
	}{
		{name: "traversal", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/../escape", mode: 0o644, typeflag: tar.TypeReg, body: []byte("bad")})
		}},
		{name: "absolute", change: func(_ string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: "/escape", mode: 0o644, typeflag: tar.TypeReg, body: []byte("bad")})
		}},
		{name: "symlink", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/link", mode: 0o777, typeflag: tar.TypeSymlink, linkname: "bin/vmmon"})
		}},
		{name: "hard link", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/hard", mode: 0o755, typeflag: tar.TypeLink, linkname: root + "/bin/vmmon"})
		}},
		{name: "device", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/device", mode: 0o600, typeflag: tar.TypeChar})
		}},
		{name: "fifo", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/fifo", mode: 0o600, typeflag: tar.TypeFifo})
		}},
		{name: "unexpected file", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			return append(entries, testArchiveEntry{name: root + "/surprise", mode: 0o644, typeflag: tar.TypeReg, body: []byte("bad")})
		}},
		{name: "wrong mode", change: func(root string, entries []testArchiveEntry) []testArchiveEntry {
			for index := range entries {
				if entries[index].name == root+"/bin/vmmon" {
					entries[index].mode = 0o644
					break
				}
			}
			return entries
		}},
		{name: "missing file", change: func(_ string, entries []testArchiveEntry) []testArchiveEntry {
			return entries[:len(entries)-1]
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			metadata, archive := createRuntimeArchive(t, test.change)
			_, err := installRuntime(context.Background(), metadata.target, installConfig{
				installRoot: t.TempDir(),
				archivePath: archive,
				metadata:    metadata,
			})
			if !IsErrorKind(err, ErrorArchiveIntegrity) {
				t.Fatalf("error = %v, want ErrorArchiveIntegrity", err)
			}
		})
	}
}

func TestInstallRuntimeRequiresReleaseDigest(t *testing.T) {
	t.Parallel()

	metadata := runtimeArchives[RuntimeTargetLinuxAMD64GNU]
	metadata.sha256 = ""
	_, err := installRuntime(context.Background(), metadata.target, installConfig{
		installRoot: t.TempDir(), metadata: metadata,
	})
	if !IsErrorKind(err, ErrorRuntimeReleaseUnavailable) {
		t.Fatalf("error = %v, want ErrorRuntimeReleaseUnavailable", err)
	}
}

func TestInstallRuntimeHonorsCancelledContext(t *testing.T) {
	t.Parallel()

	metadata, archive := createRuntimeArchive(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := installRuntime(ctx, metadata.target, installConfig{
		installRoot: t.TempDir(), archivePath: archive, metadata: metadata,
	})
	if !IsErrorKind(err, ErrorCancelled) {
		t.Fatalf("error = %v, want ErrorCancelled", err)
	}
}

func TestResolveInstallRootRejectsRelativeXDGPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative")
	_, err := resolveInstallRoot("")
	if !IsErrorKind(err, ErrorRelativeEnvironmentPath) {
		t.Fatalf("error = %v, want ErrorRelativeEnvironmentPath", err)
	}
}

func TestSafeArchivePath(t *testing.T) {
	t.Parallel()

	if _, err := safeArchivePath("root/bin/vmmon", "root"); err != nil {
		t.Fatalf("safe path rejected: %v", err)
	}
	for _, value := range []string{"", "/root/bin/vmmon", "root/../escape", "other/bin/vmmon", "root\\bin\\vmmon"} {
		if _, err := safeArchivePath(value, "root"); !IsErrorKind(err, ErrorArchiveIntegrity) {
			t.Errorf("safeArchivePath(%q) error = %v, want ErrorArchiveIntegrity", value, err)
		}
	}
}

func createRuntimeArchive(t *testing.T, change func(string, []testArchiveEntry) []testArchiveEntry) (runtimeArchiveMetadata, string) {
	t.Helper()

	metadata := runtimeArchiveMetadata{
		version: Version,
		target:  RuntimeTargetLinuxAMD64GNU,
		name:    "silo-runtime-" + Version + "-linux-amd64-gnu.tar.zst",
	}
	root := "silo-runtime-" + Version + "-linux-amd64-gnu"
	entries := make([]testArchiveEntry, 0, len(runtimeFiles))
	for relative, mode := range runtimeFiles {
		entries = append(entries, testArchiveEntry{
			name: root + "/" + relative, mode: int64(mode), typeflag: tar.TypeReg, body: []byte(relative),
		})
	}
	if change != nil {
		entries = change(root, entries)
	}

	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	writer := tar.NewWriter(encoder)
	if err := writer.WriteHeader(&tar.Header{Name: root + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatalf("write root header: %v", err)
	}
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Mode: entry.mode, Typeflag: entry.typeflag,
			Size: int64(len(entry.body)), Linkname: entry.linkname,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header %s: %v", entry.name, err)
		}
		if len(entry.body) > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatalf("write body %s: %v", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("close zstd: %v", err)
	}

	digest := sha256.Sum256(compressed.Bytes())
	metadata.sha256 = hex.EncodeToString(digest[:])
	archive := filepath.Join(t.TempDir(), metadata.name)
	if err := os.WriteFile(archive, compressed.Bytes(), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return metadata, archive
}

func TestValidateRuntimeInstallationRejectsSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "vmmon")
	if err := os.WriteFile(outside, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "bin", "vmmon")); err != nil {
		t.Fatal(err)
	}
	valid, err := validateRuntimeInstallation(root)
	if err != nil {
		t.Fatalf("validateRuntimeInstallation() failed: %v", err)
	}
	if valid {
		t.Fatal("symlink installation was accepted")
	}
}

func TestInstalledRuntimeReturnsNilWhenAbsent(t *testing.T) {
	root := t.TempDir()
	installation, err := InstalledRuntime(WithInstallRoot(root))
	if err != nil {
		t.Fatalf("InstalledRuntime() failed: %v", err)
	}
	if installation != nil {
		t.Fatalf("InstalledRuntime() = %#v, want nil", installation)
	}
}

func TestInstalledRuntimeRejectsIncompleteInstallation(t *testing.T) {
	root := t.TempDir()
	target, err := currentRuntimeTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, Version, string(target)), 0o700); err != nil {
		t.Fatal(err)
	}
	installation, err := InstalledRuntime(WithInstallRoot(root))
	if installation != nil || !IsErrorKind(err, ErrorInstallation) {
		t.Fatalf("InstalledRuntime() = %#v, %v; want invalid installation error", installation, err)
	}
}

func TestInstallLockHonorsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.lock")
	first, err := acquireInstallLock(context.Background(), path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer func() { _ = first.close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = acquireInstallLock(ctx, path)
	if !IsErrorKind(err, ErrorCancelled) && !errors.Is(err, context.Canceled) {
		t.Fatalf("second lock error = %v, want cancellation", err)
	}
}
