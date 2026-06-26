package router

import (
	"context"
	"log/slog"
	"net"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/audit"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
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

func New(hook hooks.Hook, audit *audit.Logger) *Router {
	return &Router{hook: hook, audit: audit}
}

func (r *Router) Decide(ctx context.Context, flow hooks.Flow) (hooks.RouteDecision, error) {
	decision, err := r.hook.Decide(ctx, flow)
	if err != nil {
		return hooks.RouteDecision{}, err
	}
	r.audit.RecordFlow(flow, decision)
	slog.Info("network flow decision",
		"action", decision.Action,
		"layer", decision.Layer,
		"source", decision.Source,
		"default_action", decision.DefaultAction,
		"classification_opportunity", decision.ClassificationOpportunity,
		"reason", decision.Reason,
		"rule_name", decision.RuleName,
		"endpoint_kind", decision.EndpointKind,
		"endpoint_name", decision.EndpointName,
		"credential_kind", credentialKind(decision),
		"credential_name", credentialName(decision),
		"credential_status", credentialStatus(decision),
		"protocol", flow.Protocol,
		"source_ip", flow.SourceIP.String(),
		"source_port", flow.SourcePort,
		"dest_ip", flow.DestIP.String(),
		"dest_port", flow.DestPort,
		"vm_id", flow.VMID,
		"network_id", flow.NetworkID,
	)
	return decision, nil
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
	r.audit.RecordHTTP(request, decision)
	slog.Info("http flow decision",
		"action", decision.Action,
		"layer", decision.Layer,
		"source", decision.Source,
		"default_action", decision.DefaultAction,
		"reason", decision.Reason,
		"rule_name", decision.RuleName,
		"endpoint_kind", decision.EndpointKind,
		"endpoint_name", decision.EndpointName,
		"credential_kind", credentialKind(decision),
		"credential_name", credentialName(decision),
		"credential_status", credentialStatus(decision),
		"method", request.Method,
		"host", request.Host,
		"path", request.Path,
		"source_ip", request.Flow.SourceIP.String(),
		"source_port", request.Flow.SourcePort,
		"dest_ip", request.Flow.DestIP.String(),
		"dest_port", request.Flow.DestPort,
		"vm_id", request.Flow.VMID,
		"network_id", request.Flow.NetworkID,
	)
	return decision, nil
}

func credentialKind(decision hooks.RouteDecision) string {
	if decision.Credential == nil {
		return ""
	}
	return decision.Credential.Kind
}

func credentialName(decision hooks.RouteDecision) string {
	if decision.Credential == nil {
		return ""
	}
	return decision.Credential.Name
}

func credentialStatus(decision hooks.RouteDecision) string {
	if decision.Credential != nil {
		return "selected"
	}
	return ""
}
