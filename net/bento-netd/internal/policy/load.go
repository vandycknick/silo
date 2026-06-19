package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func LoadFile(path string) (*Policy, error) {
	parser := hclparse.NewParser()
	file, diagnostics := parser.ParseHCLFile(path)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("parse policy file %s: %s", path, diagnostics.Error())
	}
	return loadBody(file.Body)
}

func loadBody(body hcl.Body) (*Policy, error) {
	content, diagnostics := body.Content(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "settings"},
			{Type: "endpoint", LabelNames: []string{"kind", "name"}},
			{Type: "credential", LabelNames: []string{"kind", "name"}},
			{Type: "tailscale", LabelNames: []string{"name"}},
			{Type: "forward", LabelNames: []string{"name"}},
			{Type: "rule", LabelNames: []string{"name"}},
		},
	})
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("decode policy file: %s", diagnostics.Error())
	}

	compiled := Default()
	rawCredentials := make([]rawCredential, 0)
	rawRules := make([]rawRule, 0)
	seenRules := make(map[string]struct{})
	settingsSeen := false

	for _, block := range content.Blocks {
		switch block.Type {
		case "settings":
			if settingsSeen {
				return nil, fmt.Errorf("duplicate settings block")
			}
			settingsSeen = true
			if err := decodeSettings(compiled, block); err != nil {
				return nil, err
			}
		case "endpoint":
			if err := decodeEndpoint(compiled, block); err != nil {
				return nil, err
			}
		case "credential":
			credential, err := decodeCredential(block)
			if err != nil {
				return nil, err
			}
			rawCredentials = append(rawCredentials, credential)
		case "tailscale", "forward":
			return nil, fmt.Errorf("%s blocks are reserved by the policy schema but not implemented by bento-netd yet", block.Type)
		case "rule":
			name := block.Labels[0]
			if _, ok := seenRules[name]; ok {
				return nil, fmt.Errorf("duplicate rule %q", name)
			}
			seenRules[name] = struct{}{}
			rule, err := decodeRule(block, len(rawRules))
			if err != nil {
				return nil, err
			}
			rawRules = append(rawRules, rule)
		}
	}

	for _, credential := range rawCredentials {
		if err := compiled.addCredential(credential); err != nil {
			return nil, err
		}
	}
	for _, rule := range rawRules {
		if err := compiled.addRule(rule); err != nil {
			return nil, err
		}
	}
	compiled.sortRules()
	return compiled, nil
}

type rawIPEndpoint struct {
	Source      []string
	Destination []string
	Protocol    string
	Ports       []PortRange
}

type rawHTTPEndpoint struct {
	Hosts []string
}

type rawCredential struct {
	Kind      string
	Name      string
	Endpoint  Ref
	Condition string
}

type rawRule struct {
	Name       string
	Endpoints  []Ref
	Credential *Ref
	Verdict    Action
	Priority   int
	Disabled   bool
	Condition  string
	Reason     string
	order      int
}

func decodeSettings(policy *Policy, block *hcl.Block) error {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "default_action"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "audit"}},
	})
	if diagnostics.HasErrors() {
		return fmt.Errorf("decode settings block: %s", diagnostics.Error())
	}
	if attr, ok := content.Attributes["default_action"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			return fmt.Errorf("decode settings.default_action: %w", err)
		}
		action, err := parseTerminalAction(value)
		if err != nil {
			return fmt.Errorf("decode settings.default_action: %w", err)
		}
		policy.DefaultAction = action
	}
	auditSeen := false
	for _, auditBlock := range content.Blocks {
		if auditSeen {
			return fmt.Errorf("duplicate settings.audit block")
		}
		auditSeen = true
		if err := decodeAuditSettings(policy, auditBlock); err != nil {
			return err
		}
	}
	return nil
}

func decodeAuditSettings(policy *Policy, block *hcl.Block) error {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "body_buffer"},
		{Name: "body_storage"},
	}})
	if diagnostics.HasErrors() {
		return fmt.Errorf("decode settings.audit block: %s", diagnostics.Error())
	}
	bodyBuffer := int64(1024 * 1024)
	bodyStorage := int64(4 * 1024)
	if attr, ok := content.Attributes["body_buffer"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			return fmt.Errorf("decode settings.audit.body_buffer: %w", err)
		}
		parsed, err := parseSize(value)
		if err != nil {
			return fmt.Errorf("decode settings.audit.body_buffer: %w", err)
		}
		bodyBuffer = parsed
	}
	if attr, ok := content.Attributes["body_storage"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			return fmt.Errorf("decode settings.audit.body_storage: %w", err)
		}
		parsed, err := parseSize(value)
		if err != nil {
			return fmt.Errorf("decode settings.audit.body_storage: %w", err)
		}
		bodyStorage = parsed
	}
	if bodyBuffer < bodyStorage {
		policy.addWarning("settings.audit.body_buffer is smaller than settings.audit.body_storage")
	}
	return nil
}

func parseSize(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("size must not be empty")
	}
	lower := strings.ToLower(value)
	for _, candidate := range []struct {
		suffix     string
		multiplier int64
	}{
		{suffix: "gib", multiplier: 1024 * 1024 * 1024},
		{suffix: "mib", multiplier: 1024 * 1024},
		{suffix: "kib", multiplier: 1024},
		{suffix: "b", multiplier: 1},
	} {
		suffix := candidate.suffix
		if !strings.HasSuffix(lower, suffix) {
			continue
		}
		number := strings.TrimSpace(value[:len(value)-len(suffix)])
		parsed, err := strconv.ParseInt(number, 10, 64)
		if err != nil || parsed < 0 {
			return 0, fmt.Errorf("invalid size %q", value)
		}
		return parsed * candidate.multiplier, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid size %q", value)
	}
	return parsed, nil
}

func decodeEndpoint(policy *Policy, block *hcl.Block) error {
	kind := block.Labels[0]
	name := block.Labels[1]
	if !hclsyntax.ValidIdentifier(name) {
		return fmt.Errorf("endpoint %q.%q name must use a traversal identifier", kind, name)
	}
	ref := Ref{Kind: kind, Name: name}
	key := ref.String()
	switch kind {
	case "cidr":
		return fmt.Errorf("endpoint %q uses removed syntax; use endpoint \"ip\" instead", key)
	case "ip":
		if _, ok := policy.ipEndpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint %q", key)
		}
		raw, err := decodeIPEndpoint(block)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		endpoint, err := compileIPEndpoint(name, raw)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		policy.ipEndpoints[key] = endpoint
	case "http":
		if _, ok := policy.httpEndpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint %q", key)
		}
		endpoint, err := decodeHTTPEndpoint(kind, name, TransportHTTPProxy, 80, block)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		if err := policy.addHTTPEndpoint(endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		policy.httpEndpoints[key] = endpoint
	case "https":
		if _, ok := policy.httpsEndpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint %q", key)
		}
		endpoint, err := decodeHTTPEndpoint(kind, name, TransportHTTPSMITM, 443, block)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		if err := policy.addHTTPEndpoint(endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		policy.httpsEndpoints[key] = endpoint
	default:
		return fmt.Errorf("unsupported endpoint kind %q", kind)
	}
	return nil
}

func decodeIPEndpoint(block *hcl.Block) (rawIPEndpoint, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "source"},
		{Name: "destination"},
		{Name: "protocol"},
		{Name: "ports"},
	}})
	if diagnostics.HasErrors() {
		return rawIPEndpoint{}, fmt.Errorf("%s", diagnostics.Error())
	}
	raw := rawIPEndpoint{Protocol: "any"}
	if attr, ok := content.Attributes["source"]; ok {
		var source []string
		if diagnostics := gohcl.DecodeExpression(attr.Expr, nil, &source); diagnostics.HasErrors() {
			return rawIPEndpoint{}, fmt.Errorf("decode source: %s", diagnostics.Error())
		}
		raw.Source = source
	}
	if attr, ok := content.Attributes["destination"]; ok {
		var destination []string
		if diagnostics := gohcl.DecodeExpression(attr.Expr, nil, &destination); diagnostics.HasErrors() {
			return rawIPEndpoint{}, fmt.Errorf("decode destination: %s", diagnostics.Error())
		}
		raw.Destination = destination
	}
	if attr, ok := content.Attributes["protocol"]; ok {
		protocol, err := decodeStringAttr(attr)
		if err != nil {
			return rawIPEndpoint{}, fmt.Errorf("decode protocol: %w", err)
		}
		raw.Protocol = protocol
	}
	if attr, ok := content.Attributes["ports"]; ok {
		ports, err := decodePortRangesAttr(attr)
		if err != nil {
			return rawIPEndpoint{}, fmt.Errorf("decode ports: %w", err)
		}
		raw.Ports = ports
	}
	return raw, nil
}

func compileIPEndpoint(name string, raw rawIPEndpoint) (*IPEndpoint, error) {
	if len(raw.Destination) == 0 && len(raw.Source) == 0 {
		return nil, fmt.Errorf("at least one source or destination entry is required")
	}
	protocol := strings.ToLower(strings.TrimSpace(raw.Protocol))
	if protocol == "" {
		protocol = "any"
	}
	switch protocol {
	case "any":
		if len(raw.Ports) > 0 {
			return nil, fmt.Errorf("protocol any cannot be combined with ports")
		}
	case "tcp", "udp", "icmp":
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	endpoint := &IPEndpoint{Name: name, Protocol: protocol, Ports: raw.Ports}
	for _, cidr := range raw.Source {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid source entry %q: %w", cidr, err)
		}
		endpoint.SourcePrefixes = append(endpoint.SourcePrefixes, prefix)
	}
	for _, cidr := range raw.Destination {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid destination entry %q: %w", cidr, err)
		}
		endpoint.DestinationPrefixes = append(endpoint.DestinationPrefixes, prefix)
	}
	return endpoint, nil
}

func decodeHTTPEndpoint(kind string, name string, transport Transport, defaultPort uint16, block *hcl.Block) (*HTTPEndpoint, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "hosts"}}})
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("%s", diagnostics.Error())
	}
	hostsAttr, ok := content.Attributes["hosts"]
	if !ok {
		return nil, fmt.Errorf("hosts is required")
	}
	var raw rawHTTPEndpoint
	if diagnostics := gohcl.DecodeExpression(hostsAttr.Expr, nil, &raw.Hosts); diagnostics.HasErrors() {
		return nil, fmt.Errorf("decode hosts: %s", diagnostics.Error())
	}
	if len(raw.Hosts) == 0 {
		return nil, fmt.Errorf("hosts must not be empty")
	}
	endpoint := &HTTPEndpoint{Kind: kind, Name: name, Family: EndpointFamilyHTTP, Transport: transport, DefaultPort: defaultPort}
	seen := make(map[string]struct{})
	for _, host := range raw.Hosts {
		binding, err := parseHostBinding(host, defaultPort)
		if err != nil {
			return nil, err
		}
		key := hostBindingKey(transport, binding.Host, binding.Port, binding.Wildcard)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		endpoint.Hosts = append(endpoint.Hosts, binding)
	}
	return endpoint, nil
}

func (p *Policy) addHTTPEndpoint(endpoint *HTTPEndpoint) error {
	ref := Ref{Kind: endpoint.Kind, Name: endpoint.Name}
	for _, binding := range endpoint.Hosts {
		if binding.Wildcard {
			continue
		}
		key := hostBindingKey(endpoint.Transport, binding.Host, binding.Port, false)
		if existing, ok := p.exactHTTPBindings[key]; ok {
			return fmt.Errorf("host %q:%d duplicates exact binding on %q", binding.Host, binding.Port, existing.String())
		}
		p.exactHTTPBindings[key] = ref
	}
	return nil
}

func hostBindingKey(transport Transport, host string, port uint16, wildcard bool) string {
	marker := "exact"
	if wildcard {
		marker = "wildcard"
	}
	return string(transport) + "|" + marker + "|" + host + "|" + strconv.Itoa(int(port))
}

func decodeCredential(block *hcl.Block) (rawCredential, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "endpoint"},
		{Name: "condition"},
	}})
	if diagnostics.HasErrors() {
		return rawCredential{}, fmt.Errorf("decode credential %q.%q: %s", block.Labels[0], block.Labels[1], diagnostics.Error())
	}
	if !hclsyntax.ValidIdentifier(block.Labels[1]) {
		return rawCredential{}, fmt.Errorf("credential %q.%q name must use a traversal identifier", block.Labels[0], block.Labels[1])
	}
	endpointAttr, ok := content.Attributes["endpoint"]
	if !ok {
		return rawCredential{}, fmt.Errorf("credential %q.%q requires endpoint", block.Labels[0], block.Labels[1])
	}
	endpoint, err := decodeRefAttr(endpointAttr)
	if err != nil {
		return rawCredential{}, fmt.Errorf("decode credential %q.%q endpoint: %w", block.Labels[0], block.Labels[1], err)
	}
	var condition string
	if conditionAttr, ok := content.Attributes["condition"]; ok {
		decoded, err := decodeStringAttr(conditionAttr)
		if err != nil {
			return rawCredential{}, fmt.Errorf("decode credential %q.%q condition: %w", block.Labels[0], block.Labels[1], err)
		}
		condition = decoded
	}
	return rawCredential{Kind: block.Labels[0], Name: block.Labels[1], Endpoint: endpoint, Condition: condition}, nil
}

func (p *Policy) addCredential(raw rawCredential) error {
	if !knownCredentialKind(raw.Kind) {
		return fmt.Errorf("unsupported credential kind %q", raw.Kind)
	}
	if raw.Endpoint.Kind != "https" {
		return fmt.Errorf("credential %q.%q must reference an https endpoint", raw.Kind, raw.Name)
	}
	if _, ok := p.httpsEndpoints[raw.Endpoint.String()]; !ok {
		return fmt.Errorf("credential %q.%q references unknown endpoint %q", raw.Kind, raw.Name, raw.Endpoint.String())
	}
	credential := &Credential{Kind: raw.Kind, Name: raw.Name, Endpoint: raw.Endpoint, Condition: raw.Condition}
	key := Ref{Kind: raw.Kind, Name: raw.Name}.String()
	if _, ok := p.credentials[key]; ok {
		return fmt.Errorf("duplicate credential %q", key)
	}
	p.credentials[key] = credential
	p.credentialsByEndpoint[raw.Endpoint.String()] = append(p.credentialsByEndpoint[raw.Endpoint.String()], credential)
	return nil
}

func knownCredentialKind(kind string) bool {
	switch kind {
	case "basic_auth", "bearer_token", "header_token", "github_oauth", "openai_codex_oauth", "aws_credential":
		return true
	default:
		return false
	}
}

func decodeRule(block *hcl.Block, order int) (rawRule, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "endpoint"},
		{Name: "endpoints"},
		{Name: "credential"},
		{Name: "condition"},
		{Name: "verdict"},
		{Name: "priority"},
		{Name: "disabled"},
		{Name: "reason"},
	}})
	if diagnostics.HasErrors() {
		return rawRule{}, fmt.Errorf("decode rule %q: %s", block.Labels[0], diagnostics.Error())
	}
	rule := rawRule{Name: block.Labels[0], order: order}
	if endpointAttr, ok := content.Attributes["endpoint"]; ok {
		endpoint, err := decodeRefAttr(endpointAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q endpoint: %w", rule.Name, err)
		}
		rule.Endpoints = append(rule.Endpoints, endpoint)
	}
	if endpointsAttr, ok := content.Attributes["endpoints"]; ok {
		if len(rule.Endpoints) > 0 {
			return rawRule{}, fmt.Errorf("rule %q uses endpoint and endpoints", rule.Name)
		}
		endpoints, err := decodeRefListAttr(endpointsAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q endpoints: %w", rule.Name, err)
		}
		rule.Endpoints = endpoints
	}
	if len(rule.Endpoints) == 0 {
		return rawRule{}, fmt.Errorf("rule %q requires endpoint or endpoints", rule.Name)
	}
	verdictAttr, ok := content.Attributes["verdict"]
	if !ok {
		return rawRule{}, fmt.Errorf("rule %q requires verdict", rule.Name)
	}
	verdict, err := decodeStringAttr(verdictAttr)
	if err != nil {
		return rawRule{}, fmt.Errorf("decode rule %q verdict: %w", rule.Name, err)
	}
	rule.Verdict, err = parseRuleAction(verdict)
	if err != nil {
		return rawRule{}, fmt.Errorf("decode rule %q verdict: %w", rule.Name, err)
	}
	if credentialAttr, ok := content.Attributes["credential"]; ok {
		credential, err := decodeRefAttr(credentialAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q credential: %w", rule.Name, err)
		}
		rule.Credential = &credential
	}
	if conditionAttr, ok := content.Attributes["condition"]; ok {
		condition, err := decodeStringAttr(conditionAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q condition: %w", rule.Name, err)
		}
		rule.Condition = condition
	}
	if priorityAttr, ok := content.Attributes["priority"]; ok {
		priority, err := decodeIntAttr(priorityAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q priority: %w", rule.Name, err)
		}
		rule.Priority = priority
	}
	if disabledAttr, ok := content.Attributes["disabled"]; ok {
		disabled, err := decodeBoolAttr(disabledAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q disabled: %w", rule.Name, err)
		}
		rule.Disabled = disabled
	}
	if reasonAttr, ok := content.Attributes["reason"]; ok {
		reason, err := decodeStringAttr(reasonAttr)
		if err != nil {
			return rawRule{}, fmt.Errorf("decode rule %q reason: %w", rule.Name, err)
		}
		rule.Reason = reason
	}
	return rule, nil
}

func (p *Policy) addRule(raw rawRule) error {
	family, err := p.validateEndpointFamily(raw.Endpoints)
	if err != nil {
		return fmt.Errorf("rule %q: %w", raw.Name, err)
	}
	rule := &Rule{
		Name:       raw.Name,
		Family:     family,
		Endpoints:  raw.Endpoints,
		Credential: raw.Credential,
		Verdict:    raw.Verdict,
		Priority:   raw.Priority,
		Disabled:   raw.Disabled,
		Condition:  raw.Condition,
		Reason:     raw.Reason,
		order:      raw.order,
	}
	if err := p.validateRuleCredential(rule); err != nil {
		return err
	}
	switch family {
	case EndpointFamilyIP:
		if raw.Condition != "" {
			return fmt.Errorf("rule %q condition is only supported for HTTP-family endpoint rules", raw.Name)
		}
		if raw.Disabled {
			return nil
		}
		p.ipRules = append(p.ipRules, rule)
	case EndpointFamilyHTTP:
		if raw.Condition != "" {
			program, err := compileCondition(raw.Condition)
			if err != nil {
				return fmt.Errorf("rule %q condition: %w", raw.Name, err)
			}
			rule.program = program
		}
		if raw.Disabled {
			return nil
		}
		p.httpRules = append(p.httpRules, rule)
	default:
		return fmt.Errorf("rule %q references unsupported endpoint family %q", raw.Name, family)
	}
	return nil
}

func (p *Policy) validateRuleCredential(rule *Rule) error {
	if rule.Credential == nil {
		return nil
	}
	credential := p.credentials[rule.Credential.String()]
	if credential == nil {
		return fmt.Errorf("rule %q references unknown credential %q", rule.Name, rule.Credential.String())
	}
	if rule.Family != EndpointFamilyHTTP {
		return fmt.Errorf("rule %q credential predicates are invalid on ip endpoints", rule.Name)
	}
	if credential.Endpoint.Kind != "https" {
		return fmt.Errorf("rule %q credential predicate must reference an https credential", rule.Name)
	}
	for _, endpoint := range rule.Endpoints {
		if endpoint == credential.Endpoint {
			return nil
		}
	}
	return fmt.Errorf("rule %q credential %q must bind to a directly referenced endpoint", rule.Name, rule.Credential.String())
}

func (p *Policy) sortRules() {
	sort.SliceStable(p.ipRules, func(i, j int) bool {
		return p.ipRules[i].Priority > p.ipRules[j].Priority
	})
	sort.SliceStable(p.httpRules, func(i, j int) bool {
		return p.httpRules[i].Priority > p.httpRules[j].Priority
	})
}

func (p *Policy) validateEndpointFamily(refs []Ref) (EndpointFamily, error) {
	if len(refs) == 0 {
		return "", fmt.Errorf("requires at least one endpoint")
	}
	family, err := p.endpointFamily(refs[0])
	if err != nil {
		return "", err
	}
	for _, ref := range refs[1:] {
		otherFamily, err := p.endpointFamily(ref)
		if err != nil {
			return "", err
		}
		if otherFamily != family {
			return "", fmt.Errorf("all endpoints in one rule must have the same family")
		}
	}
	return family, nil
}

func (p *Policy) endpointFamily(ref Ref) (EndpointFamily, error) {
	switch ref.Kind {
	case "ip":
		if _, ok := p.ipEndpoints[ref.String()]; !ok {
			return "", fmt.Errorf("references unknown endpoint %q", ref.String())
		}
		return EndpointFamilyIP, nil
	case "http":
		if _, ok := p.httpEndpoints[ref.String()]; !ok {
			return "", fmt.Errorf("references unknown endpoint %q", ref.String())
		}
		return EndpointFamilyHTTP, nil
	case "https":
		if _, ok := p.httpsEndpoints[ref.String()]; !ok {
			return "", fmt.Errorf("references unknown endpoint %q", ref.String())
		}
		return EndpointFamilyHTTP, nil
	default:
		return "", fmt.Errorf("references unsupported endpoint kind %q", ref.Kind)
	}
}
