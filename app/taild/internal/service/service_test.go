package service

import (
	"context"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestReadCapabilityHealthWithActualSDK(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = root
	r, e := runtime.Open(context.Background(), c, "instance")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	audit, e := state.OpenAudit(c.Home, 4096, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	s := &Service{Runtime: r, Audit: audit}
	peer := identity.Peer{Principals: []identity.Principal{"user:123"}, NodeID: "domain", ObservedAt: time.Now()}
	if _, e = s.Health(context.Background(), peer); e == nil {
		t.Fatal("health without vm.read accepted")
	}
	peer.Permissions.Actions = []identity.Action{identity.Read}
	health, e := s.Health(context.Background(), peer)
	if e != nil || !health.Runtime || !health.Tailnet {
		t.Fatalf("%+v %v", health, e)
	}
	if e = s.Authorize(peer, identity.Read, &authz.VM{Owner: "user:999"}); e == nil {
		t.Fatal("foreign owner accepted")
	}
}
