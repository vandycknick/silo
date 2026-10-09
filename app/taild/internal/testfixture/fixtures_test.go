package testfixture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixtureGateChild(t *testing.T) {
	if os.Getenv("SILO_TAILD_FIXTURE_CHILD") != "1" {
		return
	}
	Path(t, "SILO_TEST_RUNTIME_ROOT", true)
}

// Exercise real test-process failure/skip status, so a missing required CI
// fixture cannot silently turn the SDK acceptance lane green.
func TestRequiredFixtureGateProcessStatus(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, tt := range []struct {
		name, path, required string
		fail, skip           bool
	}{
		{"optional-absent", "", "", false, true},
		{"required-absent", "", "1", true, false},
		{"configured-missing", filepath.Join(dir, "missing"), "", true, false},
		{"configured-directory", dir, "1", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestFixtureGateChild$", "-test.v")
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "SILO_TEST_RUNTIME_ROOT=") || strings.HasPrefix(entry, "SILO_TAILD_REQUIRE_FIXTURES=") || strings.HasPrefix(entry, "SILO_TAILD_FIXTURE_CHILD=") {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "SILO_TEST_RUNTIME_ROOT="+tt.path, "SILO_TAILD_REQUIRE_FIXTURES="+tt.required, "SILO_TAILD_FIXTURE_CHILD=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("fixture child timed out: %s", output)
			}
			if (err != nil) != tt.fail || strings.Contains(string(output), "--- SKIP:") != tt.skip {
				t.Fatalf("unexpected fixture status: %v\n%s", err, output)
			}
		})
	}
}
