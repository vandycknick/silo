package router

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/netnode"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

type Router struct {
	tunnel     *netnode.Node
	policy     *policy.Policy
	policyHash string
	audit      *audit.Logger
}

func New(compiledPolicy *policy.Policy, audit *audit.Logger) *Router {
	if compiledPolicy == nil {
		compiledPolicy = policy.Default()
	}
	return &Router{policy: compiledPolicy, policyHash: compiledPolicy.PolicyHash(), audit: audit}
}

func (r *Router) Decide(ctx context.Context, flow hooks.Flow) (hooks.RouteDecision, error) {
	_ = ctx
	tailnet := r.IsTailnetDestination(flow.DestIP)
	decision := r.policy.EvaluateFlow(policy.Flow{
		TailnetDestination: tailnet,
		Protocol:           flow.Protocol, SourceIP: flow.SourceIP, SourcePort: flow.SourcePort,
		DestIP: flow.DestIP, DestPort: flow.DestPort,
	})
	converted := routeDecisionFromPolicy(decision)
	if tailnet && converted.Tunnel == nil && converted.Action != hooks.RouteDeny {
		converted.Action = hooks.RouteDeny
		converted.ClassificationOpportunity = false
		converted.Reason = "tunnel_required"
	}
	return converted, nil
}

// Classify before host NAT: translation must never erase DNS provenance or
// turn a selected tailnet address into a loopback host escape.
func (r *Router) IsTailnetDestination(address net.IP) bool {
	ip, ok := netip.AddrFromSlice(address)
	return ok && (netnode.InRange(ip) || (r.tunnel != nil && r.tunnel.IsDestination(ip)))
}

func (r *Router) SetTunnel(node *netnode.Node) { r.tunnel = node }
func (r *Router) Node() *netnode.Node          { return r.tunnel }
func (r *Router) DialTunnel(ctx context.Context, dst netip.AddrPort) (net.Conn, string, error) {
	if r.tunnel == nil {
		return nil, "tunnel_not_connected", errors.New("no tunnel node")
	}
	return r.tunnel.DialTCP(ctx, dst)
}

func (r *Router) WithFlowID(flow hooks.Flow) hooks.Flow {
	if r == nil || r.audit == nil || flow.FlowID != "" {
		return flow
	}
	flowID, ok := audit.NewFlowID()
	if !ok {
		return flow
	}
	flow.FlowID = flowID
	return flow
}

func (r *Router) HasHTTP() bool {
	return r.policy.HasHTTP()
}

func (r *Router) MatchHTTPHost(host string) bool {
	return r.policy.MatchHTTPHost(host)
}

func (r *Router) MatchHTTPHostForPort(host string, port uint16) bool {
	return r.policy.MatchHTTPHostForPort(host, port)
}

func (r *Router) ResolveHTTPHost(kind string, host string) (string, string, bool) {
	ref, _, ok := r.policy.MatchHTTPFamilyHost(kind, host)
	return ref.Kind, ref.Name, ok
}

func (r *Router) ShouldInterceptHTTP(port uint16) bool {
	return r.policy.ShouldInterceptHTTP(port)
}

func (r *Router) HasHTTPS() bool {
	return r.policy.HasHTTPS()
}

func (r *Router) ShouldInterceptHTTPS(port uint16) bool {
	return r.policy.ShouldInterceptHTTPS(port)
}

func (r *Router) MatchHTTPSHost(host string) bool {
	return r.policy.MatchHTTPSHost(host)
}

func (r *Router) ResolveHTTPSHost(host string, port uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := r.policy.ResolveHTTPSHost(host, port)
	return ref.Name, authority, certHost, ok
}

func (r *Router) ResolveHTTPSRawIP(destIP net.IP, destPort uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := r.policy.ResolveHTTPSRawIP(destIP, destPort)
	return ref.Name, authority, certHost, ok
}

func (r *Router) MatchHTTPSAuthority(host string, authority string) bool {
	return r.policy.MatchHTTPSAuthority(host, authority)
}

func (r *Router) DecideHTTP(ctx context.Context, request hooks.HTTPRequest) (hooks.RouteDecision, error) {
	_ = ctx
	decision := r.policy.EvaluateHTTP(policy.HTTPRequest{
		Flow: policy.Flow{
			Protocol: request.Flow.Protocol, SourceIP: request.Flow.SourceIP, SourcePort: request.Flow.SourcePort,
			DestIP: request.Flow.DestIP, DestPort: request.Flow.DestPort,
		},
		EndpointKind: request.EndpointKind, Host: request.Host, Method: request.Method,
		Path: request.Path, Query: request.Query, Header: request.Header,
	})
	return routeDecisionFromPolicy(decision), nil
}

func (r *Router) HasRegistries() bool {
	return r.policy.HasRegistries()
}

func (r *Router) ShouldInterceptEndpoint(kind string, port uint16) bool {
	return r.policy.ShouldInterceptEndpoint(kind, port)
}

func (r *Router) ResolveEndpointHost(kind string, host string, port uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := r.policy.ResolveEndpointHost(kind, host, port)
	return ref.Name, authority, certHost, ok
}

func (r *Router) MatchEndpointAuthority(kind string, host string, authority string) bool {
	return r.policy.MatchEndpointAuthority(kind, host, authority)
}

func (r *Router) RegistryEndpoints() []policy.RegistryEndpointConfig {
	return r.policy.RegistryEndpointConfigs()
}

func (r *Router) DecidePackage(ctx context.Context, endpointKind string, endpointName string, request policy.PackageRequest) (hooks.RouteDecision, error) {
	_ = ctx
	return routeDecisionFromPolicy(r.policy.EvaluatePackage(policy.Ref{Kind: endpointKind, Name: endpointName}, request)), nil
}

func (r *Router) RecordFlow(flow hooks.Flow, decision hooks.RouteDecision) {
	r.audit.RecordFlowForPolicy(r.policyHash, flow, decision)
}

func (r *Router) RecordFlowOutcome(flow hooks.Flow, decision hooks.RouteDecision, reason string) {
	r.audit.RecordFlowOutcomeForPolicy(r.policyHash, flow, decision, reason)
}

func (r *Router) RecordHTTP(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header) {
	r.audit.RecordHTTPRequestForPolicy(r.policyHash, request, decision, status, responseHeader)
}

func (r *Router) RecordHTTPOutcome(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header, reason string) {
	r.audit.RecordHTTPRequestOutcomeForPolicy(r.policyHash, request, decision, status, responseHeader, reason)
}

func routeDecisionFromPolicy(decision policy.Decision) hooks.RouteDecision {
	converted := hooks.RouteDecision{
		Action: routeActionFromPolicy(decision), Layer: string(decision.Layer), Source: string(decision.Source),
		DefaultAction: string(decision.DefaultAction), ClassificationOpportunity: decision.ClassificationOpportunity,
		Reason: decision.Reason, RuleName: decision.RuleName, EndpointKind: decision.EndpointKind, EndpointName: decision.EndpointName,
	}
	if decision.Tunnel != nil {
		converted.Tunnel = &hooks.Tunnel{Kind: decision.Tunnel.Kind, Name: decision.Tunnel.Name}
	}
	if decision.SelectedCredential != nil {
		converted.Credential = &hooks.Credential{
			Kind: decision.SelectedCredential.Kind, Name: decision.SelectedCredential.Name,
			Endpoint: decision.SelectedCredential.Endpoint.Name, Username: decision.SelectedCredential.Username,
			Header: decision.SelectedCredential.Header, Prefix: decision.SelectedCredential.Prefix,
			IdempotencyKey: decision.SelectedCredential.IdempotencyKey,
		}
	}
	if decision.MatchedL4 != nil {
		converted.MatchedL4 = &hooks.L4Match{
			EndpointProtocol: decision.MatchedL4.EndpointProtocol, DestPort: decision.MatchedL4.DestPort,
			PortRange: hooks.PortRange{Start: decision.MatchedL4.PortRange.Start, End: decision.MatchedL4.PortRange.End},
			Kind:      hooks.L4MatchKind(decision.MatchedL4.Kind),
		}
	}
	if facts := decision.Package; facts != nil {
		converted.Package = &hooks.Package{
			Ecosystem: facts.Ecosystem, Operation: facts.Operation, Name: facts.Name, Version: facts.Version,
			IdentityKnown: facts.IdentityKnown, AgeKnown: facts.AgeKnown, AgeHours: facts.AgeHours,
			AgeSource: facts.AgeSource, MalwareDataAvailable: facts.MalwareDataAvailable,
			Malware: facts.Malware, MalwareReason: facts.MalwareReason,
		}
	}
	return converted
}

func routeActionFromPolicy(decision policy.Decision) hooks.RouteAction {
	if decision.ClassificationOpportunity {
		return hooks.RouteClassify
	}
	if decision.Action == policy.ActionDeny {
		return hooks.RouteDeny
	}
	return hooks.RouteAllowDirect
}
