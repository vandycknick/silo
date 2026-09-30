// Package testfixture makes required offline prerequisites fail loudly in CI.
package testfixture

import (
	"os"
	"path/filepath"
	"testing"
)

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
