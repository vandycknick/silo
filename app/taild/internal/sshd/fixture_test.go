package sshd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

// nativeService opens the actual SDK runtime against a private home with a
// local OCI fixture registry, and returns a service plus a caller that owns
// every action. Cleanup drains jobs and closes the runtime.
func nativeService(t *testing.T, ctx context.Context, instance string, principals ...identity.Principal) (*service.Service, service.Caller, *testfixture.Registry) {
	t.Helper()
	registry := testfixture.OCIRegistry(t, "")
	c := config.Defaults()
	c.Home = t.TempDir()
	c.TemplatesDir = t.TempDir()
	c.PoliciesDir = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: "256MiB", Disk: "1GiB"}
	c.VM.DefaultImage = registry.Reference
	c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	r, e := runtime.Open(ctx, c, instance)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	s := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(ctx, 8), Config: c}
	t.Cleanup(func() {
		if e := s.Jobs.Wait(context.Background()); e != nil {
			t.Error(e)
		}
		_ = audit.Close()
		_ = r.Close()
	})
	limits, e := c.Limits()
	if e != nil {
		t.Fatal(e)
	}
	p := identity.Peer{Principals: principals, NodeID: "explicit-" + instance, ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: limits}}
	return s, service.Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}, registry
}
