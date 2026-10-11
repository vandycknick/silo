// Package testfixture makes required offline prerequisites fail loudly in CI.
package testfixture

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ControlEndpoint is silod's published per-UID control socket. silod spells
// it canonically, and /tmp is a symlink to /private/tmp on macOS.
func ControlEndpoint(t *testing.T) string {
	t.Helper()
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(tmp, fmt.Sprintf("silo-%d", os.Getuid()), "silod", "control.sock")
}

// TempDir is t.TempDir spelled canonically. Production configuration paths
// are canonical (bootstrap rejects anything else) and document stores walk
// them with O_NOFOLLOW, while macOS temp roots sit behind /tmp and /var links.
func TempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// Unavailable permits optional developer fixtures but never required CI skips.
func Unavailable(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("SILO_TAILD_REQUIRE_FIXTURES") == "1" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

// Path rejects a configured missing/invalid path regardless of strict mode.
// Complete runtime and bridge validation still goes through the actual SDK.
func Path(t *testing.T, name string, directory bool) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		Unavailable(t, name+" is required for this offline fixture")
	}
	if !filepath.IsAbs(value) {
		t.Fatalf("%s must be an absolute path", name)
	}
	info, err := os.Stat(value)
	if err != nil {
		t.Fatalf("configured %s is unavailable: %v", name, err)
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		t.Fatalf("configured %s has the wrong file type", name)
	}
	return value
}
