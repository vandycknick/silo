package supervision

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestStopBudgetRespectsActualLogindDelay(t *testing.T) {
	for _, tt := range []struct{ requested, system, margin, want time.Duration }{
		{90 * time.Second, 5 * time.Second, 250 * time.Millisecond, 4750 * time.Millisecond},
		{4 * time.Second, 5 * time.Second, 250 * time.Millisecond, 4 * time.Second},
		{time.Second, 100 * time.Millisecond, 250 * time.Millisecond, 0},
	} {
		if got := StopBudget(tt.requested, tt.system, tt.margin); got != tt.want {
			t.Fatal(got, tt.want)
		}
	}
}
func TestManagedShutdownAuthority(t *testing.T) {
	d := &silo.MachineData{Name: "dev", Labels: map[string]string{runtime.NameLabel: "dev", runtime.InstanceLabel: "instance", runtime.OwnerLabel: "user:1"}}
	if !Managed(d, "instance") {
		t.Fatal("valid ownership denied")
	}
	for _, field := range []string{runtime.OwnerLabel, runtime.InstanceLabel, runtime.NameLabel} {
		old := d.Labels[field]
		d.Labels[field] = "invalid"
		if Managed(d, "instance") {
			t.Fatal("invalid ownership accepted", field)
		}
		d.Labels[field] = old
	}
	if Managed(d, "") || Managed(nil, "instance") {
		t.Fatal("missing authority accepted")
	}
}

func TestActualNonrootLogindAcquireListRelease(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("nonroot logind drill")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	i, preparing, err := Acquire(ctx, config.Defaults())
	if err != nil {
		t.Skipf("real logind unavailable/denied: %v", err)
	}
	defer i.Close()
	if preparing {
		t.Skip("host is already preparing shutdown; no signal drill permitted")
	}
	type inhibitorRow struct {
		What, Who, Why, Mode string
		UID, PID             uint32
	}
	list := func() []inhibitorRow {
		var rows []inhibitorRow
		if err := i.conn.Object(i.owner, loginPath).CallWithContext(ctx, loginInterface+".ListInhibitors", 0).Store(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	found := func(rows []inhibitorRow) bool {
		for _, row := range rows {
			if row.PID == uint32(os.Getpid()) && row.UID == uint32(os.Geteuid()) && row.Who == "silo-taild" && row.Mode == "delay" && strings.Contains(row.What, "shutdown") {
				return true
			}
		}
		return false
	}
	if !found(list()) {
		t.Fatal("actual inhibitor not listed")
	}
	i.Release()
	for found(list()) {
		select {
		case <-ctx.Done():
			t.Fatal("inhibitor not released")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("real nonroot inhibitor acquired/listed/released; system delay=%s", i.maxDelay)
}

func TestActualStopAllUsesNativeManagedRecords(t *testing.T) {
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	r, err := runtime.Open(context.Background(), c, "instance")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	lock, err := state.LockHome(c.Home)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	// Real stopped disk machines need no guest boot or host shutdown.
	path := c.Home + "/input.raw"
	if err := os.WriteFile(path, []byte("stopped disk"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"managed", "unmanaged"} {
		labels := map[string]string{}
		if name == "managed" {
			labels = map[string]string{runtime.OwnerLabel: "user:1", runtime.NameLabel: name, runtime.InstanceLabel: "instance", runtime.ModeLabel: "none"}
		}
		m, err := r.SDK.CreateMachine(context.Background(), silo.DiskImage(path), silo.WithName(name), silo.WithLabels(labels))
		if err != nil {
			t.Fatal(err)
		}
		_ = m.Close()
	}
	snapshot, err := r.Reconcile(context.Background())
	if err != nil || snapshot.Unmanaged != 1 || len(snapshot.VMs) != 1 {
		t.Fatal("unlabelled orphan was not reported unmanaged", snapshot, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := StopAll(ctx, r)
	if err != nil || result.Issued != 1 || result.Finished != 1 || result.Failed != 0 {
		t.Fatal(result, err)
	}
	select {
	case <-result.Drained:
	case <-ctx.Done():
		t.Fatal("native stop goroutines not drained")
	}
}
