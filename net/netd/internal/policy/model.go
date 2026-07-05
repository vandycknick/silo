package policy

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/vandycknick/bentobox/net/netd/internal/policy/hostmatch"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type EndpointFamily string

const (
	EndpointFamilyIP   EndpointFamily = "ip"
	EndpointFamilyHTTP EndpointFamily = "http"
)

type Transport string

const (
	TransportPacketFilter Transport = "packet-filter"
	TransportHTTPProxy    Transport = "http-proxy"
	TransportHTTPSMITM    Transport = "https-mitm"
)

type DecisionLayer string

const (
	DecisionLayerFlow    DecisionLayer = "flow"
	DecisionLayerRequest DecisionLayer = "request"
)

type DecisionSource string

const (
	DecisionSourceRule    DecisionSource = "rule"
	DecisionSourceDefault DecisionSource = "default"
)

type Ref struct {
	Kind string
	Name string
}

func (r Ref) String() string {
	return r.Kind + "." + r.Name
}

func (r Ref) zero() bool {
	return r.Kind == "" && r.Name == ""
}

type Policy struct {
	diagnostics []Diagnostic
	metadata    map[string]any

	DefaultAction Action

	ipEndpoints    map[string]*IPEndpoint
	httpEndpoints  map[string]*HTTPEndpoint
	httpsEndpoints map[string]*HTTPEndpoint
	credentials    map[string]*Credential

	endpointRefsByName   map[string]Ref
	credentialRefsByName map[string]Ref
	tailscaleByName      map[string]struct{}

	credentialsByEndpoint map[string][]*Credential
	exactHTTPBindings     map[string]Ref

	ipRules   []*Rule
	httpRules []*Rule
}

type IPEndpoint struct {
	Name                string
	SourcePrefixes      []netip.Prefix
	DestinationPrefixes []netip.Prefix
	Protocol            string
	Ports               []PortRange
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

type HTTPEndpoint struct {
	Kind        string
	Name        string
	Family      EndpointFamily
	Transport   Transport
	DefaultPort uint16
	Hosts       []HostBinding
}

type HostBinding = hostmatch.Binding

type Credential struct {
	Kind           string
	Name           string
	Endpoint       Ref
	Username       string
	Header         string
	Prefix         string
	IdempotencyKey bool
	Condition      string
	condition      *httpCondition
	policy         *Policy
}

type Rule struct {
	Name       string
	Family     EndpointFamily
	Endpoints  []Ref
	Credential *Ref
	Verdict    Action
	Priority   int
	Disabled   bool
	Condition  string
	Reason     string
	order      int
	condition  *httpCondition
	policy     *Policy
}

type httpCondition struct {
	source  string
	program conditionProgram
}

type Flow struct {
	Protocol   string
	SourceIP   net.IP
	SourcePort uint16
	DestIP     net.IP
	DestPort   uint16
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

type Decision struct {
	Action                    Action
	Layer                     DecisionLayer
	Source                    DecisionSource
	DefaultAction             Action
	ClassificationOpportunity bool
	RuleName                  string
	Reason                    string
	EndpointKind              string
	EndpointName              string
	MatchedL4                 *L4Match
	MatchedFlow               Flow
	MatchedRequest            *HTTPRequest
	SelectedCredential        *Credential
}

func Default() *Policy {
	return newPolicy()
}

func newPolicy() *Policy {
	return &Policy{
		DefaultAction:         ActionAllow,
		ipEndpoints:           make(map[string]*IPEndpoint),
		httpEndpoints:         make(map[string]*HTTPEndpoint),
		httpsEndpoints:        make(map[string]*HTTPEndpoint),
		credentials:           make(map[string]*Credential),
		endpointRefsByName:    make(map[string]Ref),
		credentialRefsByName:  make(map[string]Ref),
		tailscaleByName:       make(map[string]struct{}),
		credentialsByEndpoint: make(map[string][]*Credential),
		exactHTTPBindings:     make(map[string]Ref),
	}
}

func (p *Policy) PolicyHash() string {
	return ""

}

func (p *Policy) Metadata() map[string]any {
	if p == nil || len(p.metadata) == 0 {
		return nil
	}
	metadata := make(map[string]any, len(p.metadata))
	for key, value := range p.metadata {
		metadata[key] = value
	}
	return metadata
}

func (p *Policy) Diagnostics() []Diagnostic {
	if p == nil || len(p.diagnostics) == 0 {
		return nil
	}
	diagnostics := make([]Diagnostic, len(p.diagnostics))
	copy(diagnostics, p.diagnostics)
	return diagnostics
}

func (p *Policy) Close() {
}

func (p *Policy) HasHTTP() bool {
	return p != nil && len(p.httpEndpoints) > 0
}

func (p *Policy) HasHTTPS() bool {
	return p != nil && len(p.httpsEndpoints) > 0
}

func (p *Policy) HasCredentials() bool {
	return p != nil && len(p.credentials) > 0
}

func (p *Policy) CanClassify(flow Flow) bool {
	if p == nil || strings.ToLower(flow.Protocol) != "tcp" {
		return false
	}
	return p.ShouldInterceptHTTP(flow.DestPort) || p.ShouldInterceptHTTPS(flow.DestPort)
}

func (p *Policy) ShouldInterceptHTTP(port uint16) bool {
	if p == nil {
		return false
	}
	for _, endpoint := range p.httpEndpoints {
		for _, binding := range endpoint.Hosts {
			if binding.Port == port {
				return true
			}
		}
	}
	return false
}

func (p *Policy) ShouldInterceptHTTPS(port uint16) bool {
	if p == nil {
		return false
	}
	for _, endpoint := range p.httpsEndpoints {
		for _, binding := range endpoint.Hosts {
			if binding.Port == port {
				return true
			}
		}
	}
	return false
}

func (p *Policy) MatchHTTPHost(host string) bool {
	_, _, ok := p.MatchHTTPFamilyHost("http", host)
	return ok
}

func (p *Policy) MatchHTTPHostForPort(host string, port uint16) bool {
	_, _, authority, ok := p.matchHTTPFamilyHost("http", host, hostmatch.DefaultPort("http"))
	return ok && authority.Port == port
}

func (p *Policy) MatchHTTPSHost(host string) bool {
	_, _, ok := p.MatchHTTPFamilyHost("https", host)
	return ok
}

func (p *Policy) MatchHTTPFamilyHost(kind string, host string) (Ref, *HTTPEndpoint, bool) {
	defaultPort := hostmatch.DefaultPort(kind)
	ref, endpoint, _, ok := p.matchHTTPFamilyHost(kind, host, defaultPort)
	return ref, endpoint, ok
}

func (p *Policy) ResolveHTTPSHost(host string, port uint16) (Ref, string, string, bool) {
	if port == 0 {
		port = 443
	}
	ref, _, authority, ok := p.matchHTTPFamilyHost("https", host, port)
	if !ok {
		return Ref{}, "", "", false
	}
	return ref, hostmatch.FormatAuthority(authority, 443), authority.Host, true
}

func (p *Policy) ResolveHTTPSRawIP(destIP net.IP, destPort uint16) (Ref, string, string, bool) {
	if p == nil {
		return Ref{}, "", "", false
	}
	dest, ok := addrFromIP(destIP)
	if !ok {
		return Ref{}, "", "", false
	}
	for _, endpoint := range p.httpsEndpoints {
		for _, binding := range endpoint.Hosts {
			if binding.Wildcard || binding.Port != destPort {
				continue
			}
			bindingAddr, err := netip.ParseAddr(binding.Host)
			if err != nil || bindingAddr.Unmap() != dest {
				continue
			}
			authority := hostmatch.Authority{Host: dest.String(), Port: binding.Port}
			return Ref{Kind: endpoint.Kind, Name: endpoint.Name}, hostmatch.FormatAuthority(authority, 443), authority.Host, true
		}
	}
	return Ref{}, "", "", false
}

func (p *Policy) MatchHTTPSAuthority(host string, selected string) bool {
	hostAuthority, err := hostmatch.ParseAuthority(host, 443)
	if err != nil || hostAuthority.Host == "" {
		return false
	}
	selectedAuthority, err := hostmatch.ParseAuthority(selected, 443)
	if err != nil || selectedAuthority.Host == "" {
		return false
	}
	return hostAuthority == selectedAuthority
}

func (p *Policy) matchHTTPFamilyHost(kind string, host string, defaultPort uint16) (Ref, *HTTPEndpoint, hostmatch.Authority, bool) {
	if p == nil {
		return Ref{}, nil, hostmatch.Authority{}, false
	}
	endpoints := p.httpFamilyEndpoints(kind)
	if len(endpoints) == 0 {
		return Ref{}, nil, hostmatch.Authority{}, false
	}
	parsedAuthority, err := hostmatch.ParseAuthority(host, defaultPort)
	if err != nil || parsedAuthority.Host == "" {
		return Ref{}, nil, hostmatch.Authority{}, false
	}
	var wildcardMatch *hostMatch
	for _, endpoint := range endpoints {
		for _, binding := range endpoint.Hosts {
			if !binding.Matches(parsedAuthority) {
				continue
			}
			ref := Ref{Kind: endpoint.Kind, Name: endpoint.Name}
			if !binding.Wildcard {
				return ref, endpoint, parsedAuthority, true
			}
			match := &hostMatch{ref: ref, endpoint: endpoint, suffixLength: len(binding.Host)}
			if wildcardMatch == nil || match.suffixLength > wildcardMatch.suffixLength {
				wildcardMatch = match
			}
		}
	}
	if wildcardMatch != nil {
		return wildcardMatch.ref, wildcardMatch.endpoint, parsedAuthority, true
	}
	return Ref{}, nil, hostmatch.Authority{}, false
}

type hostMatch struct {
	ref          Ref
	endpoint     *HTTPEndpoint
	suffixLength int
}

func (p *Policy) httpFamilyEndpoints(kind string) map[string]*HTTPEndpoint {
	switch kind {
	case "http":
		return p.httpEndpoints
	case "https":
		return p.httpsEndpoints
	default:
		if len(p.httpEndpoints) == 0 {
			return p.httpsEndpoints
		}
		if len(p.httpsEndpoints) == 0 {
			return p.httpEndpoints
		}
		combined := make(map[string]*HTTPEndpoint, len(p.httpEndpoints)+len(p.httpsEndpoints))
		for key, endpoint := range p.httpEndpoints {
			combined[key] = endpoint
		}
		for key, endpoint := range p.httpsEndpoints {
			combined[key] = endpoint
		}
		return combined
	}
}

func (e *IPEndpoint) match(flow Flow) (L4Match, bool) {
	if !e.matchesProtocol(flow.Protocol) {
		return L4Match{}, false
	}
	portRange, ok := e.matchPort(flow.DestPort)
	if !ok {
		return L4Match{}, false
	}
	if len(e.SourcePrefixes) > 0 {
		source, ok := addrFromIP(flow.SourceIP)
		if !ok || !prefixesContain(e.SourcePrefixes, source) {
			return L4Match{}, false
		}
	}
	if len(e.DestinationPrefixes) > 0 {
		dest, ok := addrFromIP(flow.DestIP)
		if !ok || !prefixesContain(e.DestinationPrefixes, dest) {
			return L4Match{}, false
		}
	}
	return L4Match{
		EndpointProtocol: e.Protocol,
		DestPort:         flow.DestPort,
		PortRange:        portRange,
		Kind:             l4MatchKind(portRange),
	}, true
}

func (e *IPEndpoint) matchesProtocol(protocol string) bool {
	return e.Protocol == "any" || e.Protocol == strings.ToLower(protocol)
}

func (e *IPEndpoint) matchPort(port uint16) (PortRange, bool) {
	if len(e.Ports) == 0 {
		return PortRange{}, true
	}
	for _, portRange := range e.Ports {
		if port >= portRange.Start && port <= portRange.End {
			return portRange, true
		}
	}
	return PortRange{}, false
}

func l4MatchKind(portRange PortRange) L4MatchKind {
	if portRange.Start == 0 && portRange.End == 0 {
		return L4MatchProtocolOnly
	}
	if portRange.Start == portRange.End {
		return L4MatchExactPort
	}
	return L4MatchRange
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func addrFromIP(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
