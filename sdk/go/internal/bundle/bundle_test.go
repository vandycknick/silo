package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPathUsesAbsoluteDevelopmentOverride(t *testing.T) {
	bridge := filepath.Join(t.TempDir(), platformFilename)
	if err := os.WriteFile(bridge, []byte("bridge"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SILO_GO_FFI_PATH", bridge)
	want, err := filepath.EvalSymlinks(bridge)
	if err != nil {
		t.Fatalf("resolve bridge path: %v", err)
	}
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() failed: %v", err)
	}
	if got != want {
		t.Fatalf("Path() = %q, want resolved path %q", got, want)
	}
}

func TestPathResolvesDevelopmentOverrideSymlink(t *testing.T) {
	directory := t.TempDir()
	bridge := filepath.Join(directory, platformFilename)
	if err := os.WriteFile(bridge, []byte("bridge"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "bridge-alias")
	if err := os.Symlink(bridge, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SILO_GO_FFI_PATH", alias)
	want, err := filepath.EvalSymlinks(bridge)
	if err != nil {
		t.Fatalf("resolve bridge path: %v", err)
	}
	got, err := Path()
	if err != nil {
		t.Fatalf("Path() failed: %v", err)
	}
	if got != want {
		t.Fatalf("Path() = %q, want symlink target %q", got, want)
	}
}

func TestPathRejectsRelativeDevelopmentOverride(t *testing.T) {
	t.Setenv("SILO_GO_FFI_PATH", "bridge.so")
	if _, err := Path(); err == nil {
		t.Fatal("Path() accepted a relative override")
	}
}

func TestMaterializedBridgeDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge")
	contents := []byte("bridge")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if !validDigest(path, hex.EncodeToString(digest[:])) {
		t.Fatal("validDigest rejected exact bytes")
	}
	if validDigest(path, "0000") {
		t.Fatal("validDigest accepted a mismatch")
	}
}

func TestCacheRootUsesXDGOnEveryPlatform(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	got, err := cacheRoot()
	if err != nil {
		t.Fatalf("cacheRoot() failed: %v", err)
	}
	if got != root {
		t.Fatalf("cacheRoot() = %q, want %q", got, root)
	}
}
