// Package daemon assembles the real runtime, state and job registry a service
// test needs, with explicit identity below WhoIs.
package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

// Config is the operator defaults pointed at a private home, the installed
// test runtime and, when a registry is given, its fixture image. The small
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
		c.VM.DefaultImage = registry.Reference
		c.VM.AllowedRegistries = []string{registry.Allowed()}
	}
	return c
}

// Peer is a verified observation granted every action under the configured
// ceilings: the explicit domain input native tests supply below WhoIs.
func Peer(c config.Config, nodeID string, principals ...identity.Principal) identity.Peer {
	return identity.Peer{Principals: principals, NodeID: nodeID, ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: c.Limits()}}
}

// Native is the real SDK runtime with the daemon state that lives beside it.
type Native struct {
	Runtime *runtime.Runtime
	Audit   *state.Audit
	Jobs    *jobs.Registry
}

// Open opens the runtime on c. Cleanup cancels and drains jobs, removes every
// machine left in this isolated home, then closes the audit log and runtime.
// A test that closes or reopens the runtime itself owns that handle.
func Open(t *testing.T, c config.Config, instance string, jobLimit int) Native {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, e := runtime.Open(ctx, c, instance)
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
	n := Native{Runtime: r, Audit: audit, Jobs: jobs.New(ctx, jobLimit)}
	n.Jobs.Metrics = r.Metrics
	t.Cleanup(func() {
		cancel()
		drain, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if e := n.Jobs.Wait(drain); e != nil {
			t.Error(e)
		}
		n.RemoveAll(drain)
		_ = audit.Close()
		_ = r.Close()
	})
	return n
}

// RemoveAll force-stops and removes every machine the runtime can see. Only
// an isolated test home is ever swept; shared fixtures are read-only sources.
func (n Native) RemoveAll(ctx context.Context) {
	entries, _ := n.Runtime.SDK.Inventory(ctx)
	for _, entry := range entries {
		if m, e := n.Runtime.SDK.Machine(ctx, entry.ID); e == nil {
			_, _ = m.StopWith(ctx, silo.StopOptions{Force: true, Timeout: time.Second})
			_ = m.Remove(ctx)
			_ = m.Close()
		}
	}
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
