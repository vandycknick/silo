package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
)

func (p *Policy) EvaluateFlow(flow Flow) Decision {
	if p == nil {
		return Decision{Action: ActionAllow, Layer: DecisionLayerFlow, Source: DecisionSourceDefault, DefaultAction: ActionAllow, MatchedFlow: flow}
	}
	for _, rule := range p.ipRules {
		endpoint := p.matchIPRule(rule, flow)
		if endpoint == nil {
			continue
		}
		return Decision{
			Action:                    rule.Verdict,
			Layer:                     DecisionLayerFlow,
			Source:                    DecisionSourceRule,
			DefaultAction:             p.DefaultAction,
			ClassificationOpportunity: rule.Verdict == ActionAllow && p.CanClassify(flow),
			RuleName:                  rule.Name,
			Reason:                    rule.Reason,
			EndpointKind:              "ip",
			EndpointName:              endpoint.Name,
			MatchedFlow:               flow,
		}
	}
	return Decision{
		Action:                    p.DefaultAction,
		Layer:                     DecisionLayerFlow,
		Source:                    DecisionSourceDefault,
		DefaultAction:             p.DefaultAction,
		ClassificationOpportunity: p.CanClassify(flow),
		Reason:                    defaultReason(p.DefaultAction),
		MatchedFlow:               flow,
	}
}

func (p *Policy) EvaluateHTTP(request HTTPRequest) Decision {
	if p == nil {
		return Decision{Action: ActionAllow, Layer: DecisionLayerRequest, Source: DecisionSourceDefault, DefaultAction: ActionAllow, MatchedRequest: &request}
	}
	endpointRef, endpoint, ok := p.MatchHTTPFamilyHost(request.EndpointKind, request.Host)
	if !ok {
		return Decision{
			Action:         p.DefaultAction,
			Layer:          DecisionLayerRequest,
			Source:         DecisionSourceDefault,
			DefaultAction:  p.DefaultAction,
			Reason:         "unknown_l7_endpoint",
			MatchedFlow:    request.Flow,
			MatchedRequest: &request,
		}
	}
	request.EndpointKind = endpoint.Kind
	for _, rule := range p.httpRules {
		if !rule.references(endpointRef) {
			continue
		}
		credential := p.selectedCredential(endpointRef)
		if rule.Credential != nil {
			if credential == nil || (Ref{Kind: credential.Kind, Name: credential.Name}) != *rule.Credential {
				continue
			}
		}
		matches, err := rule.matchesHTTP(request)
		if err != nil {
			return Decision{
				Action:         ActionDeny,
				Layer:          DecisionLayerRequest,
				Source:         DecisionSourceRule,
				DefaultAction:  p.DefaultAction,
				RuleName:       rule.Name,
				Reason:         "condition_error",
				EndpointKind:   endpoint.Kind,
				EndpointName:   endpoint.Name,
				MatchedFlow:    request.Flow,
				MatchedRequest: &request,
			}
		}
		if !matches {
			continue
		}
		decision := Decision{
			Action:         rule.Verdict,
			Layer:          DecisionLayerRequest,
			Source:         DecisionSourceRule,
			DefaultAction:  p.DefaultAction,
			RuleName:       rule.Name,
			Reason:         rule.Reason,
			EndpointKind:   endpoint.Kind,
			EndpointName:   endpoint.Name,
			MatchedFlow:    request.Flow,
			MatchedRequest: &request,
		}
		if rule.Verdict == ActionAllow {
			decision.SelectedCredential = credential
			decision.SelectedCredentialUnsupported = credential != nil
		}
		return decision
	}
	return Decision{
		Action:         p.DefaultAction,
		Layer:          DecisionLayerRequest,
		Source:         DecisionSourceDefault,
		DefaultAction:  p.DefaultAction,
		Reason:         defaultReason(p.DefaultAction),
		EndpointKind:   endpoint.Kind,
		EndpointName:   endpoint.Name,
		MatchedFlow:    request.Flow,
		MatchedRequest: &request,
	}
}

func defaultReason(action Action) string {
	return "default_" + string(action)
}

func (p *Policy) matchIPRule(rule *Rule, flow Flow) *IPEndpoint {
	for _, ref := range rule.Endpoints {
		endpoint := p.ipEndpoints[ref.String()]
		if endpoint != nil && endpoint.matches(flow) {
			return endpoint
		}
	}
	return nil
}

func (p *Policy) selectedCredential(endpoint Ref) *Credential {
	credentials := p.credentialsByEndpoint[endpoint.String()]
	if len(credentials) == 1 {
		return credentials[0]
	}
	return nil
}

func (r *Rule) references(endpoint Ref) bool {
	for _, candidate := range r.Endpoints {
		if candidate == endpoint {
			return true
		}
	}
	return false
}

func (r *Rule) matchesHTTP(request HTTPRequest) (bool, error) {
	if r.program == nil {
		return true, nil
	}
	value, _, err := r.program.Eval(map[string]any{
		"http": map[string]any{
			"method":  strings.ToUpper(request.Method),
			"host":    normalizedRequestHost(request),
			"path":    request.Path,
			"query":   request.Query,
			"headers": headersForCEL(request.Header),
		},
	})
	if err != nil {
		return false, err
	}
	native, err := value.ConvertToNative(reflect.TypeOf(true))
	if err != nil {
		return false, err
	}
	matched, ok := native.(bool)
	if !ok {
		return false, fmt.Errorf("condition returned %T", native)
	}
	return matched, nil
}

func compileCondition(condition string) (cel.Program, error) {
	env, err := cel.NewEnv(cel.Variable("http", cel.DynType))
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("must return bool, got %s", ast.OutputType())
	}
	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return program, nil
}

func normalizedRequestHost(request HTTPRequest) string {
	defaultPort := uint16(80)
	if request.EndpointKind == "https" {
		defaultPort = 443
	}
	authority, err := parseAuthority(request.Host, defaultPort)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(request.Host))
	}
	return authority.Host
}

func headersForCEL(header map[string][]string) map[string][]string {
	result := make(map[string][]string, len(header))
	for key, values := range header {
		copied := make([]string, len(values))
		copy(copied, values)
		result[strings.ToLower(key)] = copied
	}
	return result
}
