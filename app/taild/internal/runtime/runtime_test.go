package runtime

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestActualSDKRuntimeInventoryAndReservations(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = root
	r, e := Open(context.Background(), c, "instance")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	snapshot, e := r.Reconcile(context.Background())
	if e != nil || len(snapshot.VMs) != 0 {
		t.Fatalf("%+v %v", snapshot, e)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	hold := make(chan struct{})
	attempted := make(chan struct{}, 20)
	for i := 0; i < 20; i++ {
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
	for i := 0; i < 20; i++ {
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
	projection := Visible([]VM{{ID: "x", Name: "dev", Owner: "user:1"}, {ID: "y", Name: "other", Owner: "user:2"}}, identity.Peer{Principals: []identity.Principal{"user:1"}})
	b, e := json.Marshal(projection)
	if e != nil || len(projection) != 1 || strings.Contains(string(b), c.Home) {
		t.Fatal("unsafe projection")
	}
}
func TestMissingRuntime(t *testing.T) {
	c := config.Defaults()
	c.Home = t.TempDir()
	if _, e := Open(context.Background(), c, ""); e == nil || !strings.Contains(e.Error(), "runtime is missing") {
		t.Fatal(e)
	}
}

func TestActualBridgeRejectsInvalidRuntime(t *testing.T) {
	testfixture.Path(t, "SILO_GO_FFI_PATH", false)
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = t.TempDir()
	_, e := Open(context.Background(), c, "")
	if !silo.IsErrorKind(e, silo.ErrorRuntimeComponentInvalid) {
		t.Fatalf("actual SDK runtime validation: %v", e)
	}
}

func TestActualSDKLabelAuthorityAndResilientRecords(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = root
	r, e := Open(context.Background(), c, "instance")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ctx := context.Background()
	disk := filepath.Join(c.Home, "input.raw")
	if e = os.WriteFile(disk, []byte("stopped-only disk fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ name, owner, instance string }{{"owned", "user:1", "instance"}, {"foreign", "user:2", "instance"}, {"unmanaged", "user:1", "other-instance"}, {"broken", "user:1", "instance"}} {
		m, e := r.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName(v.name), silo.WithLabels(map[string]string{OwnerLabel: v.owner, NameLabel: v.name, InstanceLabel: v.instance, ModeLabel: "none"}))
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
	visible := Visible(snapshot.VMs, identity.Peer{Principals: []identity.Principal{"user:1"}})
	if len(visible) != 2 {
		t.Fatal(visible)
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
	cmd := exec.Command(python, "-c", `import sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute("UPDATE machine_config SET config_json=x'00' WHERE name='broken'");db.commit()`, filepath.Join(c.Home, "state.db"))
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%v %s", e, output)
	}
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
