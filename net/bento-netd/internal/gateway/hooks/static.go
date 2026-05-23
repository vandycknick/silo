package hooks

import (
	"context"
	"net/netip"
)

type StaticHook struct {
	defaultAction RouteAction
	rules         []CIDRRule
}

type CIDRRule struct {
	Name      string
	Action    RouteAction
	Reason    string
	Protocols map[string]struct{}
	Prefixes  []netip.Prefix
}

func NewStaticHook(defaultAction RouteAction, rules []CIDRRule) *StaticHook {
	return &StaticHook{
		defaultAction: defaultAction,
		rules:         rules,
	}
}

func (h *StaticHook) Decide(_ context.Context, flow Flow) (RouteDecision, error) {
	dest, ok := netip.AddrFromSlice(flow.DestIP)
	if ok {
		dest = dest.Unmap()
		for _, rule := range h.rules {
			if !rule.matchesProtocol(flow.Protocol) {
				continue
			}
			for _, prefix := range rule.Prefixes {
				if prefix.Contains(dest) {
					return RouteDecision{Action: rule.Action, Reason: rule.Reason, RuleName: rule.Name}, nil
				}
			}
		}
	}
	return RouteDecision{Action: h.defaultAction}, nil
}

func (r CIDRRule) matchesProtocol(protocol string) bool {
	if len(r.Protocols) == 0 {
		return true
	}
	_, ok := r.Protocols[protocol]
	return ok
}
