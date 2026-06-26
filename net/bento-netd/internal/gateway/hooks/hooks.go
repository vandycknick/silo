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
	Kind           string
	Name           string
	Username       string
	Header         string
	Prefix         string
	IdempotencyKey bool
}

type PortRange struct {
	Start uint16
	End   uint16
}

type L4MatchKind string

const (
	L4MatchProtocolOnly L4MatchKind = "protocol_only"
	L4MatchExactPort    L4MatchKind = "exact_port"
	L4MatchRange        L4MatchKind = "range"
)

type L4Match struct {
	EndpointProtocol string
	DestPort         uint16
	PortRange        PortRange
	Kind             L4MatchKind
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
	MatchedL4                 *L4Match
	Credential                *Credential
}

type Hook interface {
	Decide(ctx context.Context, flow Flow) (RouteDecision, error)
}
