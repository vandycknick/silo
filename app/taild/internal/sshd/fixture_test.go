package sshd

import (
	"context"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
)

// nativeService opens the actual SDK runtime against a private home with a
// local OCI fixture registry, and returns a service plus a caller that owns
// every action. Cleanup drains jobs and closes the runtime.
func nativeService(t *testing.T, instance string, principals ...identity.Principal) (*service.Service, service.Caller, *testfixture.Registry) {
	t.Helper()
	registry := testfixture.OCIRegistry(t, "")
	c := daemon.Config(t, registry)
	n := daemon.Open(t, c, instance, 8)
	s := &service.Service{Runtime: n.Runtime, Audit: n.Audit, Jobs: n.Jobs, Config: c}
	p := daemon.Peer(c, "explicit-"+instance, principals...)
	return s, service.Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}, registry
}

// offlineAudit is the decision log for a service test that needs no runtime.
func offlineAudit(t *testing.T) *state.Audit {
	t.Helper()
	audit, e := state.OpenAudit(t.TempDir(), 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = audit.Close() })
	return audit
}
