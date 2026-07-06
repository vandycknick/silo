package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/vandycknick/silo/net/netd/internal/policy/hostmatch"
)

func (p *Policy) EvaluateFlow(flow Flow) Decision {
	if p == nil {
		return Decision{Action: ActionAllow, Layer: DecisionLayerFlow, Source: DecisionSourceDefault, DefaultAction: ActionAllow, MatchedFlow: flow}
	}
	for _, rule := range p.ipRules {
		endpoint, l4Match := p.matchIPRule(rule, flow)
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
			MatchedL4:                 l4Match,
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
	if _, err := hostmatch.ParseAuthority(request.Host, hostmatch.DefaultPort(request.EndpointKind)); err != nil {
		return Decision{
			Action:         ActionDeny,
			Layer:          DecisionLayerRequest,
			Source:         DecisionSourceDefault,
			DefaultAction:  p.DefaultAction,
			Reason:         "missing_host",
			MatchedFlow:    request.Flow,
			MatchedRequest: &request,
		}
	}
	endpointRef, endpoint, ok := p.MatchHTTPFamilyHost(request.EndpointKind, request.Host)
	if !ok {
		reason := "unknown_l7_endpoint"
		if p.DefaultAction == ActionDeny {
			reason = defaultReason(p.DefaultAction)
		}
		return Decision{
			Action:         p.DefaultAction,
			Layer:          DecisionLayerRequest,
			Source:         DecisionSourceDefault,
			DefaultAction:  p.DefaultAction,
			Reason:         reason,
			MatchedFlow:    request.Flow,
			MatchedRequest: &request,
		}
	}
	request.EndpointKind = endpoint.Kind
	conditionEvaluator := newHTTPConditionEvaluator(p, request)
	defer conditionEvaluator.Close()
	credential, credentialReason := p.selectedCredential(endpointRef, conditionEvaluator)
	if credentialReason != "" {
		return Decision{
			Action:         ActionDeny,
			Layer:          DecisionLayerRequest,
			Source:         DecisionSourceDefault,
			DefaultAction:  p.DefaultAction,
			Reason:         credentialReason,
			EndpointKind:   endpoint.Kind,
			EndpointName:   endpoint.Name,
			MatchedFlow:    request.Flow,
			MatchedRequest: &request,
		}
	}
	for _, rule := range p.httpRules {
		if !rule.references(endpointRef) {
			continue
		}
		if rule.Credential != nil {
			if credential == nil || (Ref{Kind: credential.Kind, Name: credential.Name}) != *rule.Credential {
				continue
			}
		}
		matches, err := rule.matchesHTTPWithEvaluator(conditionEvaluator)
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

func (p *Policy) matchIPRule(rule *Rule, flow Flow) (*IPEndpoint, *L4Match) {
	for _, ref := range rule.Endpoints {
		endpoint := p.ipEndpoints[ref.String()]
		if endpoint == nil {
			continue
		}
		l4Match, ok := endpoint.match(flow)
		if ok {
			return endpoint, &l4Match
		}
	}
	return nil, nil
}

func (p *Policy) selectedCredential(endpoint Ref, evaluator *httpConditionEvaluator) (*Credential, string) {
	credentials := p.credentialsByEndpoint[endpoint.String()]
	if len(credentials) == 0 {
		return nil, ""
	}
	var selected *Credential
	for _, credential := range credentials {
		matches, err := credential.matchesHTTPWithEvaluator(evaluator)
		if err != nil {
			return nil, "credential_condition_error"
		}
		if !matches {
			continue
		}
		if selected != nil {
			return nil, "ambiguous_credentials"
		}
		selected = credential
	}
	return selected, ""
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
	if r == nil || r.policy == nil {
		return r.matchesHTTPWithEvaluator(nil)
	}
	evaluator := newHTTPConditionEvaluator(r.policy, request)
	defer evaluator.Close()
	return r.matchesHTTPWithEvaluator(evaluator)
}

func (r *Rule) matchesHTTPWithEvaluator(evaluator *httpConditionEvaluator) (bool, error) {
	if r == nil || r.condition == nil {
		return true, nil
	}
	return evaluator.Evaluate(r.condition)
}

func (c *Credential) matchesHTTP(request HTTPRequest) (bool, error) {
	if c == nil {
		return false, nil
	}
	if c.policy == nil {
		return c.matchesHTTPWithEvaluator(nil)
	}
	evaluator := newHTTPConditionEvaluator(c.policy, request)
	defer evaluator.Close()
	return c.matchesHTTPWithEvaluator(evaluator)
}

func (c *Credential) matchesHTTPWithEvaluator(evaluator *httpConditionEvaluator) (bool, error) {
	if c == nil {
		return false, nil
	}
	if c.condition == nil {
		return true, nil
	}
	return evaluator.Evaluate(c.condition)
}

type httpConditionEvaluator struct {
	policy  *Policy
	request HTTPRequest
	context map[string]any
	err     error
}

func newHTTPConditionEvaluator(policy *Policy, request HTTPRequest) *httpConditionEvaluator {
	return &httpConditionEvaluator{policy: policy, request: request}
}

func (e *httpConditionEvaluator) Evaluate(condition *httpCondition) (bool, error) {
	if condition == nil || condition.program == nil {
		return true, nil
	}
	if e == nil {
		return false, fmt.Errorf("policy condition %q is unavailable", condition.source)
	}
	context, err := e.Context()
	if err != nil {
		return false, err
	}
	result, _, err := condition.program.Eval(contextWithConditionDefaults(context, condition.source))
	if err != nil {
		return false, err
	}
	matches, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("policy condition %q returned %T", condition.source, result.Value())
	}
	return matches, nil
}

func (e *httpConditionEvaluator) Context() (map[string]any, error) {
	if e.context != nil || e.err != nil {
		return e.context, e.err
	}
	query, err := queryForCEL(e.request.Query)
	if err != nil {
		e.err = err
		return nil, err
	}
	context := map[string]any{
		"http.method":  strings.ToUpper(e.request.Method),
		"http.host":    normalizedRequestHost(e.request),
		"http.path":    e.request.Path,
		"http.query":   query,
		"http.headers": headersForCEL(e.request.Header),
	}
	e.context = context
	return context, nil
}

func (e *httpConditionEvaluator) Close() {
}

func normalizedRequestHost(request HTTPRequest) string {
	defaultPort := hostmatch.DefaultPort(request.EndpointKind)
	authority, err := hostmatch.ParseAuthority(request.Host, defaultPort)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(request.Host))
	}
	return authority.Host
}

func queryForCEL(rawQuery string) (map[string][]string, error) {
	parsed, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	return normalizedStringListMap(parsed, nil), nil
}

func headersForCEL(header map[string][]string) map[string][]string {
	return normalizedStringListMap(header, strings.ToLower)
}

var celMapLookupPattern = regexp.MustCompile(`http\.(query|headers)\[['"]([^'"]+)['"]\]`)

func contextWithConditionDefaults(context map[string]any, source string) map[string]any {
	matches := celMapLookupPattern.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		return context
	}
	copyContext := make(map[string]any, len(context))
	for key, value := range context {
		copyContext[key] = value
	}
	for _, match := range matches {
		mapKey := "http." + match[1]
		lookup := match[2]
		values, ok := copyContext[mapKey].(map[string][]string)
		if !ok {
			continue
		}
		copyValues := make(map[string][]string, len(values)+1)
		for key, value := range values {
			copyValues[key] = value
		}
		if _, ok := copyValues[lookup]; !ok {
			if match[1] == "headers" {
				if value, ok := copyValues[strings.ToLower(lookup)]; ok {
					copyValues[lookup] = value
				} else {
					copyValues[lookup] = []string{}
				}
			} else {
				copyValues[lookup] = []string{}
			}
		}
		copyContext[mapKey] = copyValues
	}
	return copyContext
}

func normalizedStringListMap(source map[string][]string, normalize func(string) string) map[string][]string {
	values := make(map[string][]string, len(source))
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lookup := key
		if normalize != nil {
			lookup = normalize(key)
		}
		values[lookup] = append(values[lookup], source[key]...)
	}
	return values
}
