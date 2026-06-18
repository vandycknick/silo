package hooks

import (
	"context"
	"net"
	"net/http"
)

type RouteAction string

const (
	RouteAllowDirect RouteAction = "allow_direct"
	RouteDeny        RouteAction = "deny"
	RouteClassify    RouteAction = "classify"
)

type Flow struct {
	Protocol   string
	SourceIP   net.IP
	SourcePort uint16
	DestIP     net.IP
	DestPort   uint16
	VMID       string
	NetworkID  string
}

type HTTPRequest struct {
	Flow         Flow
	EndpointKind string
	Host         string
	Method       string
	Path         string
	Query        string
	Header       http.Header
}

type Credential struct {
	Kind   string
	Name   string
	Secret string
}

type RouteDecision struct {
	Action                    RouteAction
	Layer                     string
	Source                    string
	DefaultAction             string
	ClassificationOpportunity bool
	Reason                    string
	RuleName                  string
	EndpointKind              string
	EndpointName              string
	Credential                *Credential
}

type Hook interface {
	Decide(ctx context.Context, flow Flow) (RouteDecision, error)
}
