package policy

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/cel-go/cel"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAudit Action = "audit"
)

type Ref struct {
	Kind string
	Name string
}

func (r Ref) String() string {
	return r.Kind + "." + r.Name
}

type Policy struct {
	DefaultAction Action
	auditLogPath  string

	cidrEndpoints        map[string]*CIDREndpoint
	httpsEndpoints       map[string]*HTTPSEndpoint
	credentials          map[string]*Credential
	credentialByEndpoint map[string]*Credential

	cidrRules  []*Rule
	httpsRules []*Rule
}

type CIDREndpoint struct {
	Name           string
	SourcePrefixes []netip.Prefix
	DestPrefixes   []netip.Prefix
	Protocols      map[string]struct{}
	Ports          map[uint16]struct{}
}

type HTTPSEndpoint struct {
	Name  string
	Hosts []string
}

type Credential struct {
	Kind      string
	Name      string
	Endpoint  Ref
	ValueFile string
	Value     string
}

type Rule struct {
	Name      string
	Endpoints []Ref
	Verdict   Action
	Priority  int
	Disabled  bool
	Condition string
	Reason    string
	order     int
	program   cel.Program
}

type Flow struct {
	Protocol   string
	SourceIP   net.IP
	SourcePort uint16
	DestIP     net.IP
	DestPort   uint16
}

type HTTPRequest struct {
	Flow   Flow
	Host   string
	Method string
	Path   string
	Header http.Header
}

type AuditMatch struct {
	RuleName     string
	Reason       string
	EndpointKind string
	EndpointName string
}

type Decision struct {
	Action       Action
	RuleName     string
	Reason       string
	EndpointKind string
	EndpointName string
	Audits       []AuditMatch
	Credential   *Credential
}

func Default() *Policy {
	return &Policy{
		DefaultAction:        ActionAllow,
		cidrEndpoints:        make(map[string]*CIDREndpoint),
		httpsEndpoints:       make(map[string]*HTTPSEndpoint),
		credentials:          make(map[string]*Credential),
		credentialByEndpoint: make(map[string]*Credential),
	}
}

func (p *Policy) AuditLogPath() string {
	if p == nil {
		return ""
	}
	return p.auditLogPath
}

func (p *Policy) HasHTTPS() bool {
	return p != nil && len(p.httpsEndpoints) > 0
}

func (p *Policy) MatchHTTPSHost(host string) bool {
	if p == nil {
		return false
	}
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, endpoint := range p.httpsEndpoints {
		if endpoint.matchesHost(host) {
			return true
		}
	}
	return false
}

func (e *CIDREndpoint) matches(flow Flow) bool {
	if !e.matchesProtocol(flow.Protocol) || !e.matchesPort(flow.DestPort) {
		return false
	}
	if len(e.SourcePrefixes) > 0 {
		source, ok := addrFromIP(flow.SourceIP)
		if !ok || !prefixesContain(e.SourcePrefixes, source) {
			return false
		}
	}
	if len(e.DestPrefixes) > 0 {
		dest, ok := addrFromIP(flow.DestIP)
		if !ok || !prefixesContain(e.DestPrefixes, dest) {
			return false
		}
	}
	return true
}

func (e *CIDREndpoint) matchesProtocol(protocol string) bool {
	if len(e.Protocols) == 0 {
		return true
	}
	_, ok := e.Protocols[strings.ToLower(protocol)]
	return ok
}

func (e *CIDREndpoint) matchesPort(port uint16) bool {
	if len(e.Ports) == 0 {
		return true
	}
	_, ok := e.Ports[port]
	return ok
}

func (e *HTTPSEndpoint) matchesHost(host string) bool {
	host = normalizeHost(host)
	for _, pattern := range e.Hosts {
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
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

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.Trim(host, "[]")
}

func matchHostPattern(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host != base && strings.HasSuffix(host, "."+base)
	}
	return pattern == host
}
