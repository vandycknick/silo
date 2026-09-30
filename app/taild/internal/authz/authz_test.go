package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func TestAllow(t *testing.T) {
	p := identity.Peer{Principals: []identity.Principal{"user:12"}, NodeID: "node", ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: []identity.Action{identity.Read, identity.Start}}}
	for _, tt := range []struct {
		a     identity.Action
		owner identity.Principal
		exit  int
	}{{identity.Read, "user:12", 0}, {identity.Read, "user:99", 3}, {identity.Delete, "user:12", 4}, {identity.Restart, "user:12", 4}, {identity.Reauth, "user:12", 4}} {
		e := Allow(p, tt.a, &VM{Owner: tt.owner})
		if tt.exit == 0 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			var denied *Error
			if !errors.As(e, &denied) || denied.Exit != tt.exit {
				t.Fatalf("%v", e)
			}
		}
	}
	p.Permissions.Actions = append(p.Permissions.Actions, identity.Stop)
	if e := Allow(p, identity.Restart, &VM{Owner: "user:12"}); e != nil {
		t.Fatal(e)
	}
	p.Principals = nil
	if e := Allow(p, identity.Read, nil); e == nil {
		t.Fatal("unverified peer accepted")
	}
}
