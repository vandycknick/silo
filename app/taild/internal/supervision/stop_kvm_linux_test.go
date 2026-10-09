package supervision

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestActualKVMMultiVMShutdownCoordinator(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required for real multi-VM stop")
	}
	disk := testfixture.Path(t, "SILO_TEST_LOCAL_DISK", false)
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.Components = testfixture.Components(testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true))
	ctx, done := context.WithTimeout(context.Background(), 150*time.Second)
	defer done()
	n := daemon.Open(t, c, "shutdown-instance", 8)
	r := n.Runtime
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny})
	if err != nil {
		t.Fatal(err)
	}
	var machines []*silo.Machine
	defer func() {
		for _, m := range machines {
			_ = m.Close()
		}
	}()
	for _, name := range []string{"managed-a", "managed-b", "unmanaged"} {
		labels := map[string]string{}
		if name != "unmanaged" {
			labels = map[string]string{runtime.OwnerLabel: "user:1", runtime.InstanceLabel: r.Instance, runtime.NameLabel: name, runtime.ModeLabel: "none"}
		}
		m, err := n.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName(name), silo.WithLabels(labels), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithRootDiskSize(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
		if err != nil {
			t.Fatal(err)
		}
		machines = append(machines, m)
		if _, err = m.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = m.WaitReady(ctx, 60*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if err = state.MarkShutdown(c.Home); err != nil {
		t.Fatal(err)
	}
	status, err := r.Control.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	budget := StopBudget(4*time.Second, 5*time.Second, 250*time.Millisecond)
	stopping, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	result, err := Sweep(stopping, r.Control, r.Instance, status.Generation)
	if err != nil || result.Failed != 0 || result.Finished != result.Issued {
		t.Fatalf("multi-VM stop: %+v %v", result, err)
	}
	select {
	case <-result.Drained:
	case <-stopping.Done():
		t.Fatal("native stops did not drain within budget")
	}
	for index, m := range machines {
		data, err := r.Control.Inspect(ctx, m.ID())
		if err != nil {
			t.Fatal(err)
		}
		want := silo.MachineStatusStopped
		if index == 2 {
			want = silo.MachineStatusRunning
		}
		if data.Status.Kind != want {
			t.Fatalf("%s: %s, want %s", data.Name, data.Status.Kind, want)
		}
	}
	output, err := machines[2].Exec(ctx, "/bin/sh", []string{"-c", "printf unmanaged-survived"})
	if err != nil || output.Stdout() != "unmanaged-survived" {
		t.Fatal("unmanaged VM disturbed", err)
	}
	t.Logf("two real running managed VMs stopped/drained in %s within %s, daemon lock held, unmanaged VM still executing", time.Since(start), budget)
}

// Seeds local episode transitions, not host signals. Recovery uses real logind
// observations and silod mutation admission; this is not reboot qualification.
func TestActualUnsweptCancellationRecovers(t *testing.T) {
	if os.Getenv("SILO_TEST_LOGIND") != "1" {
		t.Skip("SILO_TEST_LOGIND=1 requires an available real login1 delay inhibitor")
	}
	c := daemon.Config(t, nil)
	n := daemon.Open(t, c, "cancelled-instance", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inhibitor, preparing, err := Acquire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer inhibitor.Close()
	if preparing {
		t.Skip("host is actually preparing for shutdown")
	}
	status, err := n.Control.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	gate := &state.ShutdownGate{}
	event := loginEvent{received: time.Now()}
	inhibitor.transition(ctx, event, true, inhibitor.budget, gate)
	inhibitor.transition(ctx, event, false, inhibitor.budget, gate)
	if !gate.Pending() || state.ShutdownPending(c.Home) {
		t.Fatal("unswept cancellation must start with only the in-memory seal")
	}
	jobs := make(chan struct{})
	close(jobs)
	resumed, finished := make(chan struct{}, 1), make(chan struct{})
	go func() {
		defer close(finished)
		inhibitor.watch(ctx, c, n.Control, n.Runtime.Instance, status.Generation,
			make(chan loginEvent), gate, func() { resumed <- struct{}{} },
			func() <-chan struct{} { return jobs }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	defer func() { cancel(); <-finished }()
	select {
	case <-resumed:
		if gate.Pending() || state.ShutdownPending(c.Home) {
			t.Fatal("recovered cancellation retained admission seal")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unswept cancellation did not settle and reopen admission")
	}
}
