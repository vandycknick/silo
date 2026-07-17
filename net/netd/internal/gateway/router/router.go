package router

import (
	"context"
	"net"
	"net/http"

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

type Router struct {
	hook  hooks.Hook
	audit *audit.Logger
}

type httpsHook interface {
	HasHTTP() bool
	MatchHTTPHost(host string) bool
	MatchHTTPHostForPort(host string, port uint16) bool
	ResolveHTTPHost(kind string, host string) (string, string, bool)
	ShouldInterceptHTTP(port uint16) bool
	HasHTTPS() bool
	ShouldInterceptHTTPS(port uint16) bool
	MatchHTTPSHost(host string) bool
	ResolveHTTPSHost(host string, port uint16) (string, string, string, bool)
	ResolveHTTPSRawIP(destIP net.IP, destPort uint16) (string, string, string, bool)
	MatchHTTPSAuthority(host string, authority string) bool
	DecideHTTP(ctx context.Context, request hooks.HTTPRequest) (hooks.RouteDecision, error)
}

type registryHook interface {
	HasRegistries() bool
	ShouldInterceptEndpoint(kind string, port uint16) bool
	ResolveEndpointHost(kind string, host string, port uint16) (string, string, string, bool)
	MatchEndpointAuthority(kind string, host string, authority string) bool
	RegistryEndpoints() []hooks.RegistryEndpointConfig
	DecideAction(ctx context.Context, endpointKind string, endpointName string, facets hooks.FacetValues) (hooks.RouteDecision, error)
}

func New(hook hooks.Hook, audit *audit.Logger) *Router {
	return &Router{hook: hook, audit: audit}
}

func (r *Router) Decide(ctx context.Context, flow hooks.Flow) (hooks.RouteDecision, error) {
	decision, err := r.hook.Decide(ctx, flow)
	if err != nil {
		return hooks.RouteDecision{}, err
	}
	return decision, nil
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
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.HasHTTP()
}

func (r *Router) MatchHTTPHost(host string) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.MatchHTTPHost(host)
}

func (r *Router) MatchHTTPHostForPort(host string, port uint16) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.MatchHTTPHostForPort(host, port)
}

func (r *Router) ResolveHTTPHost(kind string, host string) (string, string, bool) {
	resolver, ok := r.hook.(httpsHook)
	if !ok {
		return "", "", false
	}
	return resolver.ResolveHTTPHost(kind, host)
}

func (r *Router) ShouldInterceptHTTP(port uint16) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.ShouldInterceptHTTP(port)
}

func (r *Router) HasHTTPS() bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.HasHTTPS()
}

func (r *Router) ShouldInterceptHTTPS(port uint16) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.ShouldInterceptHTTPS(port)
}

func (r *Router) MatchHTTPSHost(host string) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.MatchHTTPSHost(host)
}

func (r *Router) ResolveHTTPSHost(host string, port uint16) (string, string, string, bool) {
	resolver, ok := r.hook.(httpsHook)
	if !ok {
		return "", "", "", false
	}
	return resolver.ResolveHTTPSHost(host, port)
}

func (r *Router) ResolveHTTPSRawIP(destIP net.IP, destPort uint16) (string, string, string, bool) {
	resolver, ok := r.hook.(httpsHook)
	if !ok {
		return "", "", "", false
	}
	return resolver.ResolveHTTPSRawIP(destIP, destPort)
}

func (r *Router) MatchHTTPSAuthority(host string, authority string) bool {
	resolver, ok := r.hook.(httpsHook)
	return ok && resolver.MatchHTTPSAuthority(host, authority)
}

func (r *Router) DecideHTTP(ctx context.Context, request hooks.HTTPRequest) (hooks.RouteDecision, error) {
	resolver, ok := r.hook.(httpsHook)
	if !ok {
		return hooks.RouteDecision{Action: hooks.RouteAllowDirect}, nil
	}
	decision, err := resolver.DecideHTTP(ctx, request)
	if err != nil {
		return hooks.RouteDecision{}, err
	}
	return decision, nil
}

func (r *Router) HasRegistries() bool {
	resolver, ok := r.hook.(registryHook)
	return ok && resolver.HasRegistries()
}

func (r *Router) ShouldInterceptEndpoint(kind string, port uint16) bool {
	resolver, ok := r.hook.(registryHook)
	return ok && resolver.ShouldInterceptEndpoint(kind, port)
}

func (r *Router) ResolveEndpointHost(kind string, host string, port uint16) (string, string, string, bool) {
	resolver, ok := r.hook.(registryHook)
	if !ok {
		return "", "", "", false
	}
	return resolver.ResolveEndpointHost(kind, host, port)
}

func (r *Router) MatchEndpointAuthority(kind string, host string, authority string) bool {
	resolver, ok := r.hook.(registryHook)
	return ok && resolver.MatchEndpointAuthority(kind, host, authority)
}

func (r *Router) RegistryEndpoints() []hooks.RegistryEndpointConfig {
	resolver, ok := r.hook.(registryHook)
	if !ok {
		return nil
	}
	return resolver.RegistryEndpoints()
}

func (r *Router) DecideAction(ctx context.Context, endpointKind string, endpointName string, facets hooks.FacetValues) (hooks.RouteDecision, error) {
	resolver, ok := r.hook.(registryHook)
	if !ok {
		return hooks.RouteDecision{Action: hooks.RouteAllowDirect}, nil
	}
	return resolver.DecideAction(ctx, endpointKind, endpointName, facets)
}

func (r *Router) RecordFlow(flow hooks.Flow, decision hooks.RouteDecision) {
	r.audit.RecordFlow(flow, decision)
}

func (r *Router) RecordFlowOutcome(flow hooks.Flow, decision hooks.RouteDecision, reason string) {
	r.audit.RecordFlowOutcome(flow, decision, reason)
}

func (r *Router) RecordHTTP(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header) {
	r.audit.RecordHTTPRequest(request, decision, status, responseHeader)
}

func (r *Router) RecordHTTPOutcome(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header, reason string) {
	r.audit.RecordHTTPRequestOutcome(request, decision, status, responseHeader, reason)
}
