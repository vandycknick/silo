package hooks

import (
	"context"
	"net"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

type PolicyHook struct {
	policy *policy.Policy
}

func NewPolicyHook(compiled *policy.Policy) *PolicyHook {
	if compiled == nil {
		compiled = policy.Default()
	}
	return &PolicyHook{policy: compiled}
}

func (h *PolicyHook) Decide(_ context.Context, flow Flow) (RouteDecision, error) {
	decision := h.policy.EvaluateFlow(policy.Flow{
		Protocol:   flow.Protocol,
		SourceIP:   flow.SourceIP,
		SourcePort: flow.SourcePort,
		DestIP:     flow.DestIP,
		DestPort:   flow.DestPort,
	})
	return routeDecisionFromPolicy(decision), nil
}

func (h *PolicyHook) HasHTTP() bool {
	return h.policy.HasHTTP()
}

func (h *PolicyHook) MatchHTTPHost(host string) bool {
	return h.policy.MatchHTTPHost(host)
}

func (h *PolicyHook) MatchHTTPHostForPort(host string, port uint16) bool {
	return h.policy.MatchHTTPHostForPort(host, port)
}

func (h *PolicyHook) ResolveHTTPHost(kind string, host string) (string, string, bool) {
	ref, _, ok := h.policy.MatchHTTPFamilyHost(kind, host)
	return ref.Kind, ref.Name, ok
}

func (h *PolicyHook) ShouldInterceptHTTP(port uint16) bool {
	return h.policy.ShouldInterceptHTTP(port)
}

func (h *PolicyHook) HasHTTPS() bool {
	return h.policy.HasHTTPS()
}

func (h *PolicyHook) ShouldInterceptHTTPS(port uint16) bool {
	return h.policy.ShouldInterceptHTTPS(port)
}

func (h *PolicyHook) MatchHTTPSHost(host string) bool {
	return h.policy.MatchHTTPSHost(host)
}

func (h *PolicyHook) ResolveHTTPSHost(host string, port uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := h.policy.ResolveHTTPSHost(host, port)
	return ref.Name, authority, certHost, ok
}

func (h *PolicyHook) ResolveHTTPSRawIP(destIP net.IP, destPort uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := h.policy.ResolveHTTPSRawIP(destIP, destPort)
	return ref.Name, authority, certHost, ok
}

func (h *PolicyHook) MatchHTTPSAuthority(host string, authority string) bool {
	return h.policy.MatchHTTPSAuthority(host, authority)
}

func (h *PolicyHook) HasRegistries() bool {
	return h.policy.HasRegistries()
}

func (h *PolicyHook) ShouldInterceptEndpoint(kind string, port uint16) bool {
	return h.policy.ShouldInterceptEndpoint(kind, port)
}

func (h *PolicyHook) ResolveEndpointHost(kind string, host string, port uint16) (string, string, string, bool) {
	ref, authority, certHost, ok := h.policy.ResolveEndpointHost(kind, host, port)
	return ref.Name, authority, certHost, ok
}

func (h *PolicyHook) MatchEndpointAuthority(kind string, host string, authority string) bool {
	return h.policy.MatchEndpointAuthority(kind, host, authority)
}

func (h *PolicyHook) RegistryEndpoints() []RegistryEndpointConfig {
	configs := h.policy.RegistryEndpointConfigs()
	converted := make([]RegistryEndpointConfig, 0, len(configs))
	for _, config := range configs {
		converted = append(converted, RegistryEndpointConfig{
			Kind:             config.Kind,
			Name:             config.Name,
			Registries:       append([]string(nil), config.Registries...),
			MalwareFeed:      config.MalwareFeed,
			FilterPackageAge: config.FilterPackageAge,
		})
	}
	return converted
}

func (h *PolicyHook) DecideAction(_ context.Context, endpointKind string, endpointName string, facets FacetValues) (RouteDecision, error) {
	converted := make(policy.FacetValues, len(facets))
	for facet, fields := range facets {
		converted[facet] = fields
	}
	decision := h.policy.EvaluateAction(policy.Ref{Kind: endpointKind, Name: endpointName}, converted)
	return routeDecisionFromPolicy(decision), nil
}

func (h *PolicyHook) DecideHTTP(_ context.Context, request HTTPRequest) (RouteDecision, error) {
	decision := h.policy.EvaluateHTTP(policy.HTTPRequest{
		Flow: policy.Flow{
			Protocol:   request.Flow.Protocol,
			SourceIP:   request.Flow.SourceIP,
			SourcePort: request.Flow.SourcePort,
			DestIP:     request.Flow.DestIP,
			DestPort:   request.Flow.DestPort,
		},
		EndpointKind: request.EndpointKind,
		Host:         request.Host,
		Method:       request.Method,
		Path:         request.Path,
		Query:        request.Query,
		Header:       request.Header,
	})
	return routeDecisionFromPolicy(decision), nil
}

func routeDecisionFromPolicy(decision policy.Decision) RouteDecision {
	converted := RouteDecision{
		Action:                    routeActionFromPolicy(decision),
		Layer:                     string(decision.Layer),
		Source:                    string(decision.Source),
		DefaultAction:             string(decision.DefaultAction),
		ClassificationOpportunity: decision.ClassificationOpportunity,
		Reason:                    decision.Reason,
		RuleName:                  decision.RuleName,
		EndpointKind:              decision.EndpointKind,
		EndpointName:              decision.EndpointName,
	}
	if decision.SelectedCredential != nil {
		converted.Credential = &Credential{
			Kind:           decision.SelectedCredential.Kind,
			Name:           decision.SelectedCredential.Name,
			Endpoint:       decision.SelectedCredential.Endpoint.Name,
			Username:       decision.SelectedCredential.Username,
			Header:         decision.SelectedCredential.Header,
			Prefix:         decision.SelectedCredential.Prefix,
			IdempotencyKey: decision.SelectedCredential.IdempotencyKey,
		}
	}
	if decision.MatchedL4 != nil {
		converted.MatchedL4 = &L4Match{
			EndpointProtocol: decision.MatchedL4.EndpointProtocol,
			DestPort:         decision.MatchedL4.DestPort,
			PortRange: PortRange{
				Start: decision.MatchedL4.PortRange.Start,
				End:   decision.MatchedL4.PortRange.End,
			},
			Kind: L4MatchKind(decision.MatchedL4.Kind),
		}
	}
	if fields := decision.MatchedFacets["package"]; fields != nil {
		converted.Package = &Package{
			Ecosystem:            facetString(fields, "ecosystem"),
			Operation:            facetString(fields, "operation"),
			Name:                 facetString(fields, "name"),
			Version:              facetString(fields, "version"),
			IdentityKnown:        facetBool(fields, "identity_known"),
			AgeKnown:             facetBool(fields, "age_known"),
			AgeHours:             facetInt64(fields, "age_hours"),
			AgeSource:            facetString(fields, "age_source"),
			MalwareDataAvailable: facetBool(fields, "malware_data_available"),
			Malware:              facetBool(fields, "malware"),
			MalwareReason:        facetString(fields, "malware_reason"),
		}
	}
	return converted
}

func facetString(fields map[string]any, name string) string {
	value, _ := fields[name].(string)
	return value
}

func facetBool(fields map[string]any, name string) bool {
	value, _ := fields[name].(bool)
	return value
}

func facetInt64(fields map[string]any, name string) int64 {
	switch value := fields[name].(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	default:
		return 0
	}
}

func routeActionFromPolicy(decision policy.Decision) RouteAction {
	if decision.ClassificationOpportunity {
		return RouteClassify
	}
	switch decision.Action {
	case policy.ActionDeny:
		return RouteDeny
	default:
		return RouteAllowDirect
	}
}
