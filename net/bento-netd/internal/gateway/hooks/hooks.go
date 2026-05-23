package hooks

import (
	"context"
	"net"
)

type RouteAction string

const (
	RouteAllowDirect RouteAction = "allow_direct"
	RouteDeny        RouteAction = "deny"
)

type Flow struct {
	Protocol    string
	SourceIP    net.IP
	SourcePort  uint16
	DestIP      net.IP
	DestPort    uint16
	VMID        string
	NetworkID   string
	ProfileName string
}

type RouteDecision struct {
	Action   RouteAction
	Reason   string
	RuleName string
}

type Hook interface {
	Decide(ctx context.Context, flow Flow) (RouteDecision, error)
}
