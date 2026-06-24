package policy

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy/hostmatch"
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
	query, err := queryForCEL(request.Query)
	if err != nil {
		return false, err
	}
	value, _, err := r.program.Eval(map[string]any{
		"http.method":  strings.ToLower(request.Method),
		"http.host":    normalizedRequestHost(request),
		"http.path":    request.Path,
		"http.query":   query,
		"http.headers": headersForCEL(request.Header),
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
	env, err := cel.NewEnv(
		cel.Variable("http.method", cel.StringType),
		cel.Variable("http.host", cel.StringType),
		cel.Variable("http.path", cel.StringType),
		cel.Variable("http.query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("http.headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
	)
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
	normalizeHTTPMethodLiterals(ast.NativeRep().Expr())
	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return program, nil
}

func normalizedRequestHost(request HTTPRequest) string {
	defaultPort := hostmatch.DefaultPort(request.EndpointKind)
	authority, err := hostmatch.ParseAuthority(request.Host, defaultPort)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(request.Host))
	}
	return authority.Host
}

func queryForCEL(rawQuery string) (traits.Mapper, error) {
	parsed, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	return newStringListMap(parsed, nil), nil
}

func headersForCEL(header map[string][]string) traits.Mapper {
	return newStringListMap(header, strings.ToLower)
}

func newStringListMap(source map[string][]string, normalize func(string) string) traits.Mapper {
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
	return newCELStringListMap(values, normalize)
}

type celStringListMap struct {
	base      traits.Mapper
	empty     traits.Lister
	normalize func(string) string
}

func newCELStringListMap(values map[string][]string, normalize func(string) string) traits.Mapper {
	adapted := make(map[string]any, len(values))
	for key, value := range values {
		copied := make([]string, len(value))
		copy(copied, value)
		adapted[key] = copied
	}
	return &celStringListMap{
		base:      types.NewStringInterfaceMap(types.DefaultTypeAdapter, adapted),
		empty:     types.NewStringList(types.DefaultTypeAdapter, []string{}),
		normalize: normalize,
	}
}

func (m *celStringListMap) Contains(key ref.Val) ref.Val {
	_, found := m.base.Find(m.normalizeKey(key))
	return types.Bool(found)
}

func (m *celStringListMap) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return m.base.ConvertToNative(typeDesc)
}

func (m *celStringListMap) ConvertToType(typeValue ref.Type) ref.Val {
	return m.base.ConvertToType(typeValue)
}

func (m *celStringListMap) Equal(other ref.Val) ref.Val {
	return m.base.Equal(other)
}

func (m *celStringListMap) Find(key ref.Val) (ref.Val, bool) {
	value, found := m.base.Find(m.normalizeKey(key))
	if found {
		return value, true
	}
	if _, ok := key.(types.String); ok {
		return m.empty, true
	}
	return nil, false
}

func (m *celStringListMap) Get(key ref.Val) ref.Val {
	value, found := m.Find(key)
	if found {
		return value
	}
	return m.base.Get(key)
}

func (m *celStringListMap) Iterator() traits.Iterator {
	return m.base.Iterator()
}

func (m *celStringListMap) Size() ref.Val {
	return m.base.Size()
}

func (m *celStringListMap) Type() ref.Type {
	return m.base.Type()
}

func (m *celStringListMap) Value() any {
	return m.base.Value()
}

func (m *celStringListMap) normalizeKey(key ref.Val) ref.Val {
	if m.normalize == nil {
		return key
	}
	stringKey, ok := key.(types.String)
	if !ok {
		return key
	}
	return types.String(m.normalize(string(stringKey)))
}

func normalizeHTTPMethodLiterals(root celast.Expr) {
	if root == nil {
		return
	}
	var walk func(celast.Expr)
	walk = func(expr celast.Expr) {
		if expr == nil {
			return
		}
		if expr.Kind() == celast.CallKind {
			call := expr.AsCall()
			switch call.FunctionName() {
			case operators.Equals, operators.NotEquals:
				args := call.Args()
				if len(args) == 2 {
					if isHTTPMethodPath(args[0]) {
						lowercaseStringLiteral(args[1])
					} else if isHTTPMethodPath(args[1]) {
						lowercaseStringLiteral(args[0])
					}
				}
			case operators.In:
				args := call.Args()
				if len(args) == 2 && isHTTPMethodPath(args[0]) && args[1].Kind() == celast.ListKind {
					for _, element := range args[1].AsList().Elements() {
						lowercaseStringLiteral(element)
					}
				}
			case "startsWith", "endsWith", "contains":
				if call.IsMemberFunction() && isHTTPMethodPath(call.Target()) {
					for _, arg := range call.Args() {
						lowercaseStringLiteral(arg)
					}
				}
			}
		}
		switch expr.Kind() {
		case celast.CallKind:
			call := expr.AsCall()
			if call.Target() != nil {
				walk(call.Target())
			}
			for _, arg := range call.Args() {
				walk(arg)
			}
		case celast.SelectKind:
			walk(expr.AsSelect().Operand())
		case celast.ListKind:
			for _, element := range expr.AsList().Elements() {
				walk(element)
			}
		case celast.MapKind:
			for _, entry := range expr.AsMap().Entries() {
				mapEntry := entry.AsMapEntry()
				walk(mapEntry.Key())
				walk(mapEntry.Value())
			}
		case celast.StructKind:
			for _, field := range expr.AsStruct().Fields() {
				walk(field.AsStructField().Value())
			}
		case celast.ComprehensionKind:
			comprehension := expr.AsComprehension()
			walk(comprehension.IterRange())
			walk(comprehension.AccuInit())
			walk(comprehension.LoopCondition())
			walk(comprehension.LoopStep())
			walk(comprehension.Result())
		}
	}
	walk(root)
}

func isHTTPMethodPath(expr celast.Expr) bool {
	if expr == nil {
		return false
	}
	if expr.Kind() == celast.IdentKind {
		return expr.AsIdent() == "http.method"
	}
	if expr.Kind() != celast.SelectKind {
		return false
	}
	selectExpr := expr.AsSelect()
	operand := selectExpr.Operand()
	return operand != nil && operand.Kind() == celast.IdentKind && operand.AsIdent() == "http" && selectExpr.FieldName() == "method"
}

func lowercaseStringLiteral(expr celast.Expr) {
	if expr == nil || expr.Kind() != celast.LiteralKind {
		return
	}
	value := expr.AsLiteral()
	stringValue, ok := value.(types.String)
	if !ok {
		return
	}
	lower := strings.ToLower(string(stringValue))
	if lower == string(stringValue) {
		return
	}
	factory := celast.NewExprFactory()
	expr.SetKindCase(factory.NewLiteral(expr.ID(), types.String(lower)))
}
