package enroll

import (
	"context"
	"errors"
	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestActualTemporaryNodeTimeoutKeepsNativeMachineStopped(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sdk, err := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer sdk.Close()
	disk := filepath.Join(home, "input.raw")
	if err = os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "pending" }`)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := sdk.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("pending"), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer endpoint.Close()
	c := config.Defaults()
	c.Enrollment.Mode = "interactive"
	c.Enrollment.Timeout = "750ms"
	manager := &Manager{Config: c, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: endpoint.URL}, Registry: NewRegistry()}
	err = manager.Enroll(ctx, machine, data, "user:1", false, func(line string) { t.Log(line) }, nil)
	var failure *authz.Error
	if !errors.As(err, &failure) || failure.Exit != 9 {
		t.Fatal(err)
	}
	if requests.Load() == 0 {
		t.Fatal("control protocol was not contacted")
	}
	after, err := machine.Inspect(ctx)
	if err != nil || after.Status.Kind != silo.MachineStatusStopped {
		t.Fatal("pending VM booted", after, err)
	}
	if _, err = os.Stat(data.Network.Tailscale.StateDir + ".pending"); !os.IsNotExist(err) {
		t.Fatal("pending server state leaked", err)
	}
	lease, err := machine.LeaseNodeState(ctx)
	if err != nil {
		t.Fatal("lease not released", err)
	}
	lease.Close()
	if err = machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
