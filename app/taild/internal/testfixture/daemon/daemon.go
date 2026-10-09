// Package daemon assembles the real runtime, state and job registry a service
// test needs, with explicit identity below WhoIs.
package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

// Config is the operator defaults pointed at a private home, the installed
// test runtime and, when a registry is given, its allowlist. The small
// resources keep stopped-VM tests cheap; tests that boot raise memory.
func Config(t *testing.T, registry *testfixture.Registry) config.Config {
	t.Helper()
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.TemplatesDir = t.TempDir()
	c.PoliciesDir = t.TempDir()
	c.Components = testfixture.Components(testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true))
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: 256 << 20, Disk: 1 << 30}
	if registry != nil {
		c.VM.AllowedRegistries = []string{registry.Allowed()}
	}
	return c
}

// Peer is a verified observation granted every action under the configured
// ceilings: the explicit domain input native tests supply below WhoIs.
func Peer(c config.Config, nodeID string, principals ...identity.Principal) identity.Peer {
	return identity.Peer{Principals: principals, NodeID: nodeID, ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: c.Limits()}}
}

// Native owns a real silod manager, helper session runtime, and independent writer.
type Native struct {
	Runtime *runtime.Runtime
	Audit   *state.Audit
	Jobs    *jobs.Registry
	Control *control.Client
	SDK     *silo.Runtime // Independent fixture writer; never a production fallback.
	config  config.Config
}

// Open launches silod on c.Home with optional integrations disabled. Cleanup
// drains jobs and sessions and cleans VMs while management is alive, then closes
// local runtimes/client and finally terminates and reaps silod.
func Open(t *testing.T, c config.Config, instance string, jobLimit int) Native {
	t.Helper()
	manager, c := launchManager(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	r, e := runtime.Open(ctx, c, instance, manager)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		cancel()
		_ = r.Close()
		t.Fatal(e)
	}
	sdk, e := silo.Open(ctx, silo.WithHome(c.Home), silo.WithRuntimeComponents(c.Components))
	if e != nil {
		cancel()
		_ = audit.Close()
		_ = r.Close()
		t.Fatal(e)
	}
	n := Native{Runtime: r, Audit: audit, Jobs: jobs.New(ctx, jobLimit), Control: manager, SDK: sdk, config: c}
	n.Jobs.Metrics = r.Metrics
	t.Cleanup(func() {
		cancel()
		drain, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if e := n.Jobs.Wait(drain); e != nil {
			t.Error(e)
		}
		cleanup, finish := context.WithTimeout(context.Background(), 30*time.Second)
		defer finish()
		if e := n.RemoveAll(cleanup); e != nil {
			t.Error("fixture VM cleanup:", e)
		}
		_ = audit.Close()
		_ = r.Close()
		_ = sdk.Close()
	})
	return n
}

// RemoveAll force-stops and removes every machine the runtime can see. Only
// an isolated test home is ever swept; shared fixtures are read-only sources.
func (n Native) RemoveAll(ctx context.Context) error {
	entries, err := n.Control.Inventory(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		data, err := n.Control.Inspect(ctx, entry.ID)
		if err != nil {
			if !silo.IsErrorKind(err, silo.ErrorMachineNotFound) {
				failures = append(failures, err)
			}
			continue
		}
		if data.Status.Kind != silo.MachineStatusStopped && !(data.Status.Kind == silo.MachineStatusError && data.RunID == nil) {
			if data.RunID == nil {
				failures = append(failures, errors.New("fixture running generation unavailable"))
				continue
			}
			_, err = n.Control.Stop(ctx, entry.ID, data.RunID, silo.StopOptions{Force: true, Timeout: time.Second})
		}
		if err == nil || silo.IsErrorKind(err, silo.ErrorMachineNotRunning) {
			err = n.Control.Remove(ctx, entry.ID)
		}
		if err != nil && !silo.IsErrorKind(err, silo.ErrorMachineNotFound) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Writer opens an independent native fixture context for deliberate local writer
// races and guest setup. Service management must use Runtime.Control instead.
func Writer(t *testing.T, c config.Config) *silo.Runtime {
	t.Helper()
	sdk, err := silo.Open(context.Background(), silo.WithHome(c.Home), silo.WithRuntimeComponents(c.Components))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdk.Close() })
	return sdk
}

// Reopen replaces only the helper session context; the same manager remains alive.
func (n Native) Reopen(t *testing.T, c config.Config, instance string) *runtime.Runtime {
	t.Helper()
	c.Home, c.Components, c.BridgePath = n.config.Home, n.config.Components, n.config.BridgePath
	r, err := runtime.Open(context.Background(), c, instance, n.Control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// WaitOperation fails on a rejected submission, otherwise blocks until the
// operation finishes and returns its final record.
func WaitOperation(t *testing.T, reg *jobs.Registry, peer identity.Peer, op jobs.Operation, submitted error) jobs.Operation {
	t.Helper()
	if submitted != nil {
		t.Fatal(submitted)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for {
		v, changed, e := reg.Observe(peer, op.ID)
		if e != nil {
			t.Fatal(e)
		}
		if v.Finished != nil {
			return v
		}
		select {
		case <-ctx.Done():
			t.Fatal("operation deadline")
		case <-changed:
		}
	}
}

// Succeeded waits for the operation and fails the test unless it succeeded.
func Succeeded(t *testing.T, reg *jobs.Registry, peer identity.Peer, op jobs.Operation, submitted error) {
	t.Helper()
	if v := WaitOperation(t, reg, peer, op, submitted); v.State != "succeeded" {
		t.Fatalf("operation %+v error %+v", v, v.Error)
	}
}
