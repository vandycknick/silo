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
	FlowID     string
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

type FacetValues map[string]map[string]any

type RegistryEndpointConfig struct {
	Kind             string
	Name             string
	Registries       []string
	MalwareFeed      string
	FilterPackageAge uint32
}

type Package struct {
	Ecosystem            string
	Operation            string
	Name                 string
	Version              string
	IdentityKnown        bool
	AgeKnown             bool
	AgeHours             int64
	AgeSource            string
	MalwareDataAvailable bool
	Malware              bool
	MalwareReason        string
}

type Credential struct {
	Kind           string
	Name           string
	Endpoint       string
	Username       string
	Header         string
	Prefix         string
	IdempotencyKey bool
}

type Tunnel struct {
	Kind string
	Name string
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
	Tunnel                    *Tunnel
	Package                   *Package
}

type Hook interface {
	Decide(ctx context.Context, flow Flow) (RouteDecision, error)
}
