package policy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
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
	DefaultAction Action
	warnings      []string

	ipEndpoints    map[string]*IPEndpoint
	httpEndpoints  map[string]*HTTPEndpoint
	httpsEndpoints map[string]*HTTPEndpoint
	credentials    map[string]*Credential

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

type HTTPEndpoint struct {
	Kind        string
	Name        string
	Family      EndpointFamily
	Transport   Transport
	DefaultPort uint16
	Hosts       []HostBinding
}

type HostBinding struct {
	Pattern  string
	Host     string
	Port     uint16
	Wildcard bool
}

type Credential struct {
	Kind      string
	Name      string
	Endpoint  Ref
	Condition string
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
	program    cel.Program
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
	Action                        Action
	Layer                         DecisionLayer
	Source                        DecisionSource
	DefaultAction                 Action
	ClassificationOpportunity     bool
	RuleName                      string
	Reason                        string
	EndpointKind                  string
	EndpointName                  string
	MatchedFlow                   Flow
	MatchedRequest                *HTTPRequest
	SelectedCredential            *Credential
	SelectedCredentialUnsupported bool
}

func Default() *Policy {
	return &Policy{
		DefaultAction:         ActionAllow,
		ipEndpoints:           make(map[string]*IPEndpoint),
		httpEndpoints:         make(map[string]*HTTPEndpoint),
		httpsEndpoints:        make(map[string]*HTTPEndpoint),
		credentials:           make(map[string]*Credential),
		credentialsByEndpoint: make(map[string][]*Credential),
		exactHTTPBindings:     make(map[string]Ref),
	}
}

func (p *Policy) Warnings() []string {
	if p == nil || len(p.warnings) == 0 {
		return nil
	}
	warnings := make([]string, len(p.warnings))
	copy(warnings, p.warnings)
	return warnings
}

func (p *Policy) addWarning(message string) {
	p.warnings = append(p.warnings, message)
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
	return p != nil && port == 80 && len(p.httpEndpoints) > 0
}

func (p *Policy) ShouldInterceptHTTPS(port uint16) bool {
	return p != nil && port == 443 && len(p.httpsEndpoints) > 0
}

func (p *Policy) MatchHTTPHost(host string) bool {
	_, _, ok := p.MatchHTTPFamilyHost("http", host)
	return ok
}

func (p *Policy) MatchHTTPSHost(host string) bool {
	_, _, ok := p.MatchHTTPFamilyHost("https", host)
	return ok
}

func (p *Policy) MatchHTTPFamilyHost(kind string, host string) (Ref, *HTTPEndpoint, bool) {
	if p == nil {
		return Ref{}, nil, false
	}
	endpoints := p.httpFamilyEndpoints(kind)
	if len(endpoints) == 0 {
		return Ref{}, nil, false
	}
	defaultPort := uint16(80)
	if kind == "https" {
		defaultPort = 443
	}
	authority, err := parseAuthority(host, defaultPort)
	if err != nil || authority.Host == "" {
		return Ref{}, nil, false
	}
	var wildcardMatch *hostMatch
	for _, endpoint := range endpoints {
		for _, binding := range endpoint.Hosts {
			if !binding.matches(authority) {
				continue
			}
			ref := Ref{Kind: endpoint.Kind, Name: endpoint.Name}
			if !binding.Wildcard {
				return ref, endpoint, true
			}
			match := &hostMatch{ref: ref, endpoint: endpoint, suffixLength: len(binding.Host)}
			if wildcardMatch == nil || match.suffixLength > wildcardMatch.suffixLength {
				wildcardMatch = match
			}
		}
	}
	if wildcardMatch != nil {
		return wildcardMatch.ref, wildcardMatch.endpoint, true
	}
	return Ref{}, nil, false
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

func (e *IPEndpoint) matches(flow Flow) bool {
	if !e.matchesProtocol(flow.Protocol) || !e.matchesPort(flow.DestPort) {
		return false
	}
	if len(e.SourcePrefixes) > 0 {
		source, ok := addrFromIP(flow.SourceIP)
		if !ok || !prefixesContain(e.SourcePrefixes, source) {
			return false
		}
	}
	if len(e.DestinationPrefixes) > 0 {
		dest, ok := addrFromIP(flow.DestIP)
		if !ok || !prefixesContain(e.DestinationPrefixes, dest) {
			return false
		}
	}
	return true
}

func (e *IPEndpoint) matchesProtocol(protocol string) bool {
	return e.Protocol == "any" || e.Protocol == strings.ToLower(protocol)
}

func (e *IPEndpoint) matchesPort(port uint16) bool {
	if len(e.Ports) == 0 {
		return true
	}
	for _, portRange := range e.Ports {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func (b HostBinding) matches(authority authority) bool {
	if b.Port != authority.Port {
		return false
	}
	if !b.Wildcard {
		return b.Host == authority.Host
	}
	return authority.Host != b.Host && strings.HasSuffix(authority.Host, "."+b.Host)
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

type authority struct {
	Host string
	Port uint16
}

func parseHostBinding(pattern string, defaultPort uint16) (HostBinding, error) {
	if strings.Contains(pattern, "://") || strings.Contains(pattern, "/") {
		return HostBinding{}, fmt.Errorf("host %q must not include a scheme or path", pattern)
	}
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return HostBinding{}, fmt.Errorf("host must not be empty")
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	if wildcard {
		pattern = strings.TrimPrefix(pattern, "*.")
		if pattern == "" || strings.Contains(pattern, "*") {
			return HostBinding{}, fmt.Errorf("wildcard host %q is invalid", "*."+pattern)
		}
	}
	authority, err := parseAuthority(pattern, defaultPort)
	if err != nil {
		return HostBinding{}, err
	}
	if _, err := netip.ParseAddr(authority.Host); err == nil && wildcard {
		return HostBinding{}, fmt.Errorf("wildcard host %q cannot be an IP address", "*."+authority.Host)
	}
	canonicalPattern := authority.Host
	if wildcard {
		canonicalPattern = "*." + authority.Host
	}
	return HostBinding{Pattern: canonicalPattern, Host: authority.Host, Port: authority.Port, Wildcard: wildcard}, nil
}

func parseAuthority(input string, defaultPort uint16) (authority, error) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return authority{}, nil
	}
	if strings.Contains(input, "://") {
		return authority{}, fmt.Errorf("authority %q must not include a scheme", input)
	}
	host := input
	port := defaultPort
	if parsedHost, parsedPort, err := net.SplitHostPort(input); err == nil {
		host = parsedHost
		decodedPort, err := parsePort(parsedPort)
		if err != nil {
			return authority{}, err
		}
		port = decodedPort
	} else if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		host = strings.Trim(input, "[]")
	} else if strings.Count(input, ":") == 1 {
		left, right, _ := strings.Cut(input, ":")
		if right != "" {
			decodedPort, err := parsePort(right)
			if err == nil {
				host = left
				port = decodedPort
			}
		}
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return authority{}, fmt.Errorf("authority host must not be empty")
	}
	return authority{Host: host, Port: port}, nil
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q is out of range", value)
	}
	return uint16(port), nil
}
