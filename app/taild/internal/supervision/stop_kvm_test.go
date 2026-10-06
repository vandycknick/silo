package supervision

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
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
	r, err := runtime.Open(ctx, c, "shutdown-instance")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	lock, err := state.LockHome(c.Home)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny})
	if err != nil {
		t.Fatal(err)
	}
	var machines []*silo.Machine
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, m := range machines {
			_, _ = m.StopWith(cleanup, silo.StopOptions{Force: true})
			_ = m.Remove(cleanup)
			_ = m.Close()
		}
	}()
	for _, name := range []string{"managed-a", "managed-b", "unmanaged"} {
		labels := map[string]string{}
		if name != "unmanaged" {
			labels = map[string]string{runtime.OwnerLabel: "user:1", runtime.InstanceLabel: r.Instance, runtime.NameLabel: name, runtime.ModeLabel: "none"}
		}
		m, err := r.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName(name), silo.WithLabels(labels), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithRootDiskSize(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
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
	budget := StopBudget(4*time.Second, 5*time.Second, 250*time.Millisecond)
	stopping, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	result, err := StopAll(stopping, r)
	if err != nil || result.Issued != 2 || result.Finished != 2 || result.Failed != 0 {
		t.Fatalf("multi-VM stop: %+v %v", result, err)
	}
	select {
	case <-result.Drained:
	case <-stopping.Done():
		t.Fatal("native stops did not drain within budget")
	}
	for index, m := range machines {
		data, err := m.Inspect(ctx)
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
