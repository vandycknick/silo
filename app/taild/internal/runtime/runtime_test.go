package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/control"
	. "github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestActualSDKRuntimeInventoryAndReservations(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.Components = testfixture.Components(root)
	n := daemon.Open(t, c, "instance", 1)
	r := n.Runtime
	snapshot, e := r.Reconcile(context.Background())
	if e != nil || len(snapshot.VMs) != 0 {
		t.Fatalf("%+v %v", snapshot, e)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	hold := make(chan struct{})
	attempted := make(chan struct{}, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, e := r.Reserve(context.Background(), "dev", nil)
			if e == nil {
				won.Add(1)
			}
			attempted <- struct{}{}
			if e == nil {
				<-hold
				release()
			}
		}()
	}
	for range 20 {
		<-attempted
	}
	if won.Load() != 1 {
		t.Fatalf("reservation winners: %d", won.Load())
	}
	// A second synchronous collision is independent of contender scheduling.
	if _, e = r.Reserve(context.Background(), "dev", nil); e == nil {
		t.Fatal("reservation collision accepted")
	}
	close(hold)
	wg.Wait()
	if _, e = r.Reserve(context.Background(), "peer", []string{"peer"}); e == nil {
		t.Fatal("visible tailnet collision accepted")
	}
	if _, e = os.Stat(filepath.Join(c.Home, "state.db")); e != nil {
		t.Fatal("SDK did not open real home:", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = n.Control.Inventory(context.Background()); e != nil {
		t.Fatalf("closing session runtime closed externally owned manager: %v", e)
	}
}
func TestMissingRuntime(t *testing.T) {
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.BridgePath = ""
	if _, e := Open(context.Background(), c, "", &control.Client{}); e == nil {
		t.Fatal(e)
	}
}

func TestActualBridgeRejectsInvalidRuntime(t *testing.T) {
	testfixture.Path(t, "SILO_GO_FFI_PATH", false)
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.Components = testfixture.Components(t.TempDir())
	_, e := silo.Open(context.Background(), silo.WithHome(c.Home), silo.WithRuntimeComponents(c.Components))
	if !silo.IsErrorKind(e, silo.ErrorRuntimeComponentInvalid) {
		t.Fatalf("actual SDK runtime validation: %v", e)
	}
}

func TestActualSDKLabelAuthorityAndResilientRecords(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.Components = testfixture.Components(root)
	n := daemon.Open(t, c, "instance", 1)
	r := n.Runtime
	ctx := context.Background()
	disk := filepath.Join(c.Home, "input.raw")
	if e := os.WriteFile(disk, []byte("stopped-only disk fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ name, owner, instance string }{{"owned", "user:1", "instance"}, {"foreign", "user:2", "instance"}, {"unmanaged", "user:1", "other-instance"}, {"broken", "user:1", "instance"}} {
		m, e := n.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName(v.name), silo.WithLabels(map[string]string{OwnerLabel: v.owner, NameLabel: v.name, InstanceLabel: v.instance, ModeLabel: "none"}))
		if e != nil {
			t.Fatal(e)
		}
		if e = m.Close(); e != nil {
			t.Fatal(e)
		}
	}
	snapshot, e := r.Reconcile(ctx)
	if e != nil || len(snapshot.VMs) != 3 || snapshot.Unmanaged != 1 {
		t.Fatalf("%+v %v", snapshot, e)
	}
	owned := 0
	for _, vm := range snapshot.VMs {
		if vm.Owner == "user:1" {
			owned++
		}
	}
	if owned != 2 {
		t.Fatal(snapshot.VMs)
	}
	if _, e = r.Reserve(ctx, "foreign", nil); e == nil {
		t.Fatal("another owner's exact local name was not reserved")
	}
	if _, e = r.Reserve(ctx, "unmanaged", nil); e == nil {
		t.Fatal("unmanaged exact local name was not reserved")
	}
	python, e := exec.LookPath("python3")
	if e != nil {
		testfixture.Unavailable(t, "python3 sqlite3 required for actual corrupt-record inventory")
	}
	cmd := exec.Command(python, "-c", `import sqlite3,sys,json
db=sqlite3.connect(sys.argv[1]);original=db.execute("SELECT hex(config_json), typeof(config_json) FROM machine_config WHERE name='broken'").fetchone()
sys.stdout.write(json.dumps(original));db.execute("UPDATE machine_config SET config_json=x'00' WHERE name='broken'");db.commit()`, filepath.Join(c.Home, "state.db"))
	original, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	// Restore the exact stored value before the fixture's authoritative cleanup.
	t.Cleanup(func() {
		restore := exec.Command(python, "-c", `import sqlite3,sys,json
encoded,kind=json.load(sys.stdin);value=bytes.fromhex(encoded)
if kind == "text": value=value.decode("utf-8")
db=sqlite3.connect(sys.argv[1]);db.execute("UPDATE machine_config SET config_json=? WHERE name='broken'", (value,));db.commit()`, filepath.Join(c.Home, "state.db"))
		restore.Stdin = bytes.NewReader(original)
		if output, err := restore.CombinedOutput(); err != nil {
			t.Errorf("restore corrupt-record fixture: %v %s", err, output)
		}
	})
	snapshot, e = r.Reconcile(ctx)
	if e != nil || len(snapshot.VMs) != 2 || snapshot.Unreadable < 1 {
		t.Fatalf("healthy records hidden by corruption: %+v %v", snapshot, e)
	}
	if _, e = r.Reserve(ctx, "broken", nil); e == nil {
		t.Fatal("unreadable indexed record lost exact name reservation")
	}
	b, e := json.Marshal(snapshot.VMs)
	if e != nil || strings.Contains(string(b), c.Home) || strings.Contains(string(b), "input.raw") {
		t.Fatalf("unsafe projection: %s %v", b, e)
	}
}

func TestManagedLabelAuthority(t *testing.T) {
	d := &silo.MachineData{Name: "dev", Labels: map[string]string{NameLabel: "dev", InstanceLabel: "instance", OwnerLabel: "user:1"}}
	if !Managed(d, "instance") {
		t.Fatal("valid ownership denied")
	}
	for _, field := range []string{OwnerLabel, InstanceLabel, NameLabel} {
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
