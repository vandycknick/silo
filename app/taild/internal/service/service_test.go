package service

import (
	"context"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func TestReadCapabilityHealthWithActualManagement(t *testing.T) {
	s := actualService(t)
	peer := identity.Peer{Principals: []identity.Principal{"user:123"}, NodeID: "domain", ObservedAt: time.Now()}
	if _, e := s.Health(context.Background(), peer); e == nil {
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
