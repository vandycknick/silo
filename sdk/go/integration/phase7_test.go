//go:build silo_e2e

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func TestPhase7RealNativeKVM(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 is required")
	}
	root, disk := os.Getenv("SILO_TEST_RUNTIME_ROOT"), os.Getenv("SILO_TEST_DISK_IMAGE")
	if root == "" || disk == "" {
		t.Skip("SILO_TEST_RUNTIME_ROOT and SILO_TEST_DISK_IMAGE are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	home := t.TempDir()
	if evidence := os.Getenv("SILO_TEST_MACHINE_HOME"); evidence != "" {
		if err := os.Mkdir(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		home = evidence
	}
	runtime, err := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	machine, err := runtime.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("phase7-kvm"), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithVsock(true), silo.WithMachineNetwork(silo.NoNetwork()), silo.WithGuestUser("silo", 1000, 1000, "/home/silo"))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	defer func() {
		cleanup := context.Background()
		_, _ = machine.StopWith(cleanup, silo.StopOptions{Timeout: time.Second, Force: true})
		if !t.Failed() {
			_ = machine.Remove(cleanup)
		} else {
			t.Logf("failed stopped fixture retained at %s", home)
		}
	}()
	if _, err := machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := machine.WaitReady(ctx, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if data.Status.Ready == nil || !*data.Status.Ready || data.Status.GuestReady == nil || !*data.Status.GuestReady || data.RunID == nil || data.GuestUser == nil || data.GuestUser.Name != "silo" {
		t.Fatalf("actual guest readiness and user: %#v", data)
	}
	pinPath := filepath.Join(data.MachineDir, "ssh", "known_host")
	pin, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.WriteFile(pinPath, pin, 0600) }()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := binary.BigEndian.AppendUint32(nil, uint32(len("ssh-ed25519")))
	wire = append(wire, "ssh-ed25519"...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(public)))
	wire = append(wire, public...)
	if err := os.WriteFile(pinPath, []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(wire)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	untrusted, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if untrusted.Status.Ready == nil || *untrusted.Status.Ready || untrusted.Status.GuestReady == nil || !*untrusted.Status.GuestReady || untrusted.RunID == nil || *untrusted.RunID != *data.RunID {
		t.Fatalf("pin mismatch must retain the current guest report but deny readiness: %#v", untrusted)
	}
	if _, err := machine.WaitReady(ctx, 250*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady accepted untrusted retained GuestReady: %v", err)
	}
	if err := os.WriteFile(pinPath, pin, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.WaitReady(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	t.Log("actual SSH pin mismatch: retained GuestReady=true, Ready=false, WaitReady timed out; restored pin recovers readiness")
	cpus := uint8(2)
	if _, err := machine.Update(ctx, silo.MachineUpdate{CPUs: &cpus}); err == nil {
		t.Fatal("running update accepted")
	}
	output, err := machine.Exec(ctx, "/bin/sh", []string{"-c", `printf 'TERM=%s\n' "$TERM"; /bin/stty size; /bin/id -u; /bin/id -g`}, silo.WithExecTTY(true), silo.WithExecInitialPTYSize(37, 119), silo.WithExecTerm("s7-test-terminal"))
	if err != nil {
		t.Fatal(err)
	}
	terminal := output.TerminalOutput()
	if !strings.Contains(terminal, "TERM=s7-test-terminal") || !strings.Contains(terminal, "37 119") || strings.Count(terminal, "1000") != 2 {
		t.Fatalf("actual guest stty/TERM/uid/gid: %q, result %#v", terminal, output.Result())
	}
	t.Logf("first run %s: real guest output %q", *data.RunID, terminal)
	if _, err := machine.StopWith(ctx, silo.StopOptions{Timeout: 20 * time.Millisecond, Force: true}); err != nil {
		t.Fatal(err)
	}
	name := "phase7-kvm-renamed"
	labels := map[string]string{"io.silo.taild.name": name}
	diskSize := silo.Mebibytes(128)
	data, err = machine.Update(ctx, silo.MachineUpdate{Name: &name, Labels: &labels, CPUs: &cpus, RootDiskSize: &diskSize, GuestUser: &silo.GuestUser{Name: "silo", UID: 1000, GID: 1000, Home: "/home/silo"}})
	if err != nil {
		t.Fatal(err)
	}
	if data.Name != name || data.RootDiskSize == nil || data.RootDiskSize.Bytes() != diskSize.Bytes() || *data.CPUs != 2 || data.Labels["io.silo.taild.name"] != name {
		t.Fatalf("real stopped update: %#v", data)
	}
	if _, err := machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	data, err = machine.WaitReady(ctx, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	output, err = machine.Shell(ctx, `/bin/id -u`, silo.WithExecTTY(true), silo.WithExecInitialPTYSize(24, 80), silo.WithExecTerm("dumb"))
	if err != nil || !strings.Contains(output.TerminalOutput(), "1000") {
		t.Fatalf("second boot user execution: %v %v", output, err)
	}
	t.Logf("second run %s: name and grown disk persist; guest user uid1000", *data.RunID)
	if _, err := machine.StopWith(ctx, silo.StopOptions{Timeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
