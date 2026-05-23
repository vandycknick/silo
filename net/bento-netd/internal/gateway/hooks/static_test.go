package hooks

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestStaticHookDeniesMatchingDestinationCIDR(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	hook := NewStaticHook(RouteAllowDirect, []CIDRRule{{
		Name:     "deny-private",
		Action:   RouteDeny,
		Reason:   "private range blocked",
		Prefixes: []netip.Prefix{prefix},
	}})

	decision, err := hook.Decide(context.Background(), Flow{Protocol: "tcp", DestIP: net.ParseIP("10.1.2.3")})
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if decision.Action != RouteDeny {
		t.Fatalf("expected deny, got %s", decision.Action)
	}
	if decision.RuleName != "deny-private" {
		t.Fatalf("expected rule name, got %q", decision.RuleName)
	}
}

func TestStaticHookHonorsProtocolFilter(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	hook := NewStaticHook(RouteAllowDirect, []CIDRRule{{
		Name:      "deny-private-tcp",
		Action:    RouteDeny,
		Protocols: map[string]struct{}{"tcp": {}},
		Prefixes:  []netip.Prefix{prefix},
	}})

	decision, err := hook.Decide(context.Background(), Flow{Protocol: "udp", DestIP: net.ParseIP("10.1.2.3")})
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if decision.Action != RouteAllowDirect {
		t.Fatalf("expected allow, got %s", decision.Action)
	}
}
