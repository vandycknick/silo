package hooks

import (
	"context"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy"
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

func (h *PolicyHook) ResolveHTTPHost(kind string, host string) (string, string, bool) {
	ref, _, ok := h.policy.MatchHTTPFamilyHost(kind, host)
	return ref.Kind, ref.Name, ok
}

func (h *PolicyHook) HasHTTPS() bool {
	return h.policy.HasHTTPS()
}

func (h *PolicyHook) MatchHTTPSHost(host string) bool {
	return h.policy.MatchHTTPSHost(host)
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
	if decision.SelectedCredential != nil && !decision.SelectedCredentialUnsupported {
		converted.Credential = &Credential{
			Kind: decision.SelectedCredential.Kind,
			Name: decision.SelectedCredential.Name,
		}
	}
	return converted
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
