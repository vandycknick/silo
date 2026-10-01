package silo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeStateLeaseCrossProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if home := os.Getenv("SILO_LEASE_CHILD_HOME"); home != "" {
		r, err := Open(ctx, WithHome(home), WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		m, err := r.Machine(ctx, "leased")
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if _, err = m.Inspect(ctx); err != nil {
			t.Fatal("inspect while leased", err)
		}
		if _, err = m.Start(ctx); !IsErrorKind(err, ErrorInvalidMachineUpdate) || !strings.Contains(err.Error(), "node state busy") {
			t.Fatal("Start did not fail busy", err)
		}
		cpus := uint8(2)
		if _, err = m.Update(ctx, MachineUpdate{CPUs: &cpus}); !IsErrorKind(err, ErrorInvalidMachineUpdate) {
			t.Fatal("Update did not fail busy", err)
		}
		if err = m.Remove(ctx); !IsErrorKind(err, ErrorInvalidMachineUpdate) {
			t.Fatal("Remove did not fail busy", err)
		}
		return
	}
	r, home := phase7Runtime(t)
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := r.CreateMachine(ctx, DiskImage(disk), WithName("leased"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	lease, err := m.LeaseNodeState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, exe, "-test.run=^TestNodeStateLeaseCrossProcess$", "-test.timeout=20s")
	child.Env = append(os.Environ(), "SILO_LEASE_CHILD_HOME="+home)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, output)
	}
	data, err := m.Inspect(ctx)
	if err != nil || data.Name != "leased" || data.Status.Kind != MachineStatusStopped {
		t.Fatal("lease changed machine", data, err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	cpus := uint8(2)
	if _, err = m.Update(ctx, MachineUpdate{CPUs: &cpus}); err != nil {
		t.Fatal(err)
	}
	if err = m.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
