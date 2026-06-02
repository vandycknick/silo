package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
)

func (p *Policy) EvaluateFlow(flow Flow) Decision {
	if p == nil {
		return Decision{Action: ActionAllow}
	}
	decision := Decision{Action: p.DefaultAction}
	for _, rule := range p.cidrRules {
		endpoint := p.matchCIDRRule(rule, flow)
		if endpoint == nil {
			continue
		}
		if rule.Verdict == ActionAudit {
			decision.Audits = append(decision.Audits, AuditMatch{
				RuleName:     rule.Name,
				Reason:       rule.Reason,
				EndpointKind: "cidr",
				EndpointName: endpoint.Name,
			})
			continue
		}
		decision.Action = rule.Verdict
		decision.RuleName = rule.Name
		decision.Reason = rule.Reason
		decision.EndpointKind = "cidr"
		decision.EndpointName = endpoint.Name
		return decision
	}
	return decision
}

func (p *Policy) EvaluateHTTP(request HTTPRequest) Decision {
	if p == nil {
		return Decision{Action: ActionAllow}
	}
	decision := Decision{Action: p.DefaultAction}
	for _, rule := range p.httpsRules {
		endpointRef, endpoint := p.matchHTTPSRule(rule, request)
		if endpoint == nil {
			continue
		}
		matches, err := rule.matchesHTTP(request)
		if err != nil || !matches {
			continue
		}
		if rule.Verdict == ActionAudit {
			decision.Audits = append(decision.Audits, AuditMatch{
				RuleName:     rule.Name,
				Reason:       rule.Reason,
				EndpointKind: "https",
				EndpointName: endpoint.Name,
			})
			continue
		}
		decision.Action = rule.Verdict
		decision.RuleName = rule.Name
		decision.Reason = rule.Reason
		decision.EndpointKind = "https"
		decision.EndpointName = endpoint.Name
		if rule.Verdict == ActionAllow {
			decision.Credential = p.credentialByEndpoint[endpointRef.String()]
		}
		return decision
	}
	return decision
}

func (p *Policy) matchCIDRRule(rule *Rule, flow Flow) *CIDREndpoint {
	for _, ref := range rule.Endpoints {
		endpoint := p.cidrEndpoints[ref.String()]
		if endpoint != nil && endpoint.matches(flow) {
			return endpoint
		}
	}
	return nil
}

func (p *Policy) matchHTTPSRule(rule *Rule, request HTTPRequest) (Ref, *HTTPSEndpoint) {
	host := normalizeHost(request.Host)
	for _, ref := range rule.Endpoints {
		endpoint := p.httpsEndpoints[ref.String()]
		if endpoint != nil && endpoint.matchesHost(host) {
			return ref, endpoint
		}
	}
	return Ref{}, nil
}

func (r *Rule) matchesHTTP(request HTTPRequest) (bool, error) {
	if r.program == nil {
		return true, nil
	}
	value, _, err := r.program.Eval(map[string]any{
		"http": map[string]any{
			"method":  request.Method,
			"host":    normalizeHost(request.Host),
			"path":    request.Path,
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

func headersForCEL(header map[string][]string) map[string]any {
	result := make(map[string]any, len(header))
	for key, values := range header {
		if len(values) == 1 {
			result[strings.ToLower(key)] = values[0]
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		result[strings.ToLower(key)] = copied
	}
	return result
}
