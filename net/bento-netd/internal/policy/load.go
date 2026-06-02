package policy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
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

	for _, block := range content.Blocks {
		switch block.Type {
		case "settings":
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

type rawCIDREndpoint struct {
	CIDRs       []string `hcl:"cidrs,optional"`
	DestCIDRs   []string `hcl:"dest_cidrs,optional"`
	SourceCIDRs []string `hcl:"source_cidrs,optional"`
	Protocols   []string `hcl:"protocols,optional"`
	Ports       []int    `hcl:"ports,optional"`
}

type rawHTTPSEndpoint struct {
	Hosts []string `hcl:"hosts"`
}

type rawCredential struct {
	Kind      string
	Name      string
	Endpoint  Ref
	ValueFile string
}

type rawRule struct {
	Name      string
	Endpoints []Ref
	Verdict   Action
	Priority  int
	Disabled  bool
	Condition string
	Reason    string
	order     int
}

func decodeSettings(policy *Policy, block *hcl.Block) error {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "default_action"},
		{Name: "audit_log"},
	}})
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
	if attr, ok := content.Attributes["audit_log"]; ok {
		path, err := decodeStringAttr(attr)
		if err != nil {
			return fmt.Errorf("decode settings.audit_log: %w", err)
		}
		if path != "" && !filepath.IsAbs(path) {
			return fmt.Errorf("settings.audit_log must be an absolute path: %s", path)
		}
		policy.auditLogPath = path
	}
	return nil
}

func decodeEndpoint(policy *Policy, block *hcl.Block) error {
	kind := block.Labels[0]
	name := block.Labels[1]
	ref := Ref{Kind: kind, Name: name}
	key := ref.String()
	switch kind {
	case "cidr":
		if _, ok := policy.cidrEndpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint %q", key)
		}
		var raw rawCIDREndpoint
		if diagnostics := gohcl.DecodeBody(block.Body, nil, &raw); diagnostics.HasErrors() {
			return fmt.Errorf("decode endpoint %q: %s", key, diagnostics.Error())
		}
		endpoint, err := compileCIDREndpoint(name, raw)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		policy.cidrEndpoints[key] = endpoint
	case "https":
		if _, ok := policy.httpsEndpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint %q", key)
		}
		var raw rawHTTPSEndpoint
		if diagnostics := gohcl.DecodeBody(block.Body, nil, &raw); diagnostics.HasErrors() {
			return fmt.Errorf("decode endpoint %q: %s", key, diagnostics.Error())
		}
		endpoint, err := compileHTTPSEndpoint(name, raw)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %w", key, err)
		}
		policy.httpsEndpoints[key] = endpoint
	default:
		return fmt.Errorf("unsupported endpoint kind %q", kind)
	}
	return nil
}

func compileCIDREndpoint(name string, raw rawCIDREndpoint) (*CIDREndpoint, error) {
	if len(raw.CIDRs) > 0 && len(raw.DestCIDRs) > 0 {
		return nil, fmt.Errorf("use cidrs or dest_cidrs, not both")
	}
	destCIDRs := raw.DestCIDRs
	if len(raw.CIDRs) > 0 {
		destCIDRs = raw.CIDRs
	}
	if len(destCIDRs) == 0 && len(raw.SourceCIDRs) == 0 {
		return nil, fmt.Errorf("at least one source_cidrs, dest_cidrs, or cidrs entry is required")
	}
	endpoint := &CIDREndpoint{
		Name:      name,
		Protocols: make(map[string]struct{}),
		Ports:     make(map[uint16]struct{}),
	}
	for _, cidr := range raw.SourceCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid source_cidrs entry %q: %w", cidr, err)
		}
		endpoint.SourcePrefixes = append(endpoint.SourcePrefixes, prefix)
	}
	for _, cidr := range destCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid dest cidr entry %q: %w", cidr, err)
		}
		endpoint.DestPrefixes = append(endpoint.DestPrefixes, prefix)
	}
	for _, protocol := range raw.Protocols {
		protocol = strings.ToLower(protocol)
		switch protocol {
		case "", "any":
			if len(raw.Protocols) > 1 {
				return nil, fmt.Errorf("protocol any cannot be combined with other protocols")
			}
			endpoint.Protocols = map[string]struct{}{}
		case "tcp", "udp":
			endpoint.Protocols[protocol] = struct{}{}
		default:
			return nil, fmt.Errorf("unsupported protocol %q", protocol)
		}
	}
	for _, port := range raw.Ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d is out of range", port)
		}
		endpoint.Ports[uint16(port)] = struct{}{}
	}
	return endpoint, nil
}

func compileHTTPSEndpoint(name string, raw rawHTTPSEndpoint) (*HTTPSEndpoint, error) {
	if len(raw.Hosts) == 0 {
		return nil, fmt.Errorf("hosts must not be empty")
	}
	endpoint := &HTTPSEndpoint{Name: name}
	seen := make(map[string]struct{})
	for _, host := range raw.Hosts {
		if strings.Contains(host, "://") || strings.Contains(host, "/") {
			return nil, fmt.Errorf("host %q must not include a scheme or path", host)
		}
		host = normalizeHost(host)
		if host == "" {
			return nil, fmt.Errorf("host must not be empty")
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		endpoint.Hosts = append(endpoint.Hosts, host)
	}
	return endpoint, nil
}

func decodeCredential(block *hcl.Block) (rawCredential, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "endpoint"},
		{Name: "value_file"},
	}})
	if diagnostics.HasErrors() {
		return rawCredential{}, fmt.Errorf("decode credential %q.%q: %s", block.Labels[0], block.Labels[1], diagnostics.Error())
	}
	endpointAttr, ok := content.Attributes["endpoint"]
	if !ok {
		return rawCredential{}, fmt.Errorf("credential %q.%q requires endpoint", block.Labels[0], block.Labels[1])
	}
	endpoint, err := decodeRefAttr(endpointAttr)
	if err != nil {
		return rawCredential{}, fmt.Errorf("decode credential %q.%q endpoint: %w", block.Labels[0], block.Labels[1], err)
	}
	valueFileAttr, ok := content.Attributes["value_file"]
	if !ok {
		return rawCredential{}, fmt.Errorf("credential %q.%q requires value_file", block.Labels[0], block.Labels[1])
	}
	valueFile, err := decodeStringAttr(valueFileAttr)
	if err != nil {
		return rawCredential{}, fmt.Errorf("decode credential %q.%q value_file: %w", block.Labels[0], block.Labels[1], err)
	}
	return rawCredential{Kind: block.Labels[0], Name: block.Labels[1], Endpoint: endpoint, ValueFile: valueFile}, nil
}

func (p *Policy) addCredential(raw rawCredential) error {
	if raw.Kind != "bearer_token" {
		return fmt.Errorf("unsupported credential kind %q", raw.Kind)
	}
	if raw.Endpoint.Kind != "https" {
		return fmt.Errorf("credential %q.%q must reference an https endpoint", raw.Kind, raw.Name)
	}
	if _, ok := p.httpsEndpoints[raw.Endpoint.String()]; !ok {
		return fmt.Errorf("credential %q.%q references unknown endpoint %q", raw.Kind, raw.Name, raw.Endpoint.String())
	}
	if existing := p.credentialByEndpoint[raw.Endpoint.String()]; existing != nil {
		return fmt.Errorf(
			"credential %q.%q references endpoint %q, but credential %q already references that endpoint; credentials and endpoints must be one-to-one",
			raw.Kind,
			raw.Name,
			raw.Endpoint.String(),
			Ref{Kind: existing.Kind, Name: existing.Name}.String(),
		)
	}
	if !filepath.IsAbs(raw.ValueFile) {
		return fmt.Errorf("credential %q.%q value_file must be absolute: %s", raw.Kind, raw.Name, raw.ValueFile)
	}
	valueBytes, err := os.ReadFile(raw.ValueFile)
	if err != nil {
		return fmt.Errorf("read credential %q.%q value_file %s: %w", raw.Kind, raw.Name, raw.ValueFile, err)
	}
	value := strings.TrimSuffix(string(valueBytes), "\n")
	if value == "" {
		return fmt.Errorf("credential %q.%q value_file is empty", raw.Kind, raw.Name)
	}
	credential := &Credential{Kind: raw.Kind, Name: raw.Name, Endpoint: raw.Endpoint, ValueFile: raw.ValueFile, Value: value}
	key := Ref{Kind: raw.Kind, Name: raw.Name}.String()
	if _, ok := p.credentials[key]; ok {
		return fmt.Errorf("duplicate credential %q", key)
	}
	p.credentials[key] = credential
	p.credentialByEndpoint[raw.Endpoint.String()] = credential
	return nil
}

func decodeRule(block *hcl.Block, order int) (rawRule, error) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "endpoint"},
		{Name: "endpoints"},
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
	if raw.Disabled {
		return nil
	}
	if err := validateEndpointFamily(raw.Endpoints); err != nil {
		return fmt.Errorf("rule %q: %w", raw.Name, err)
	}
	rule := &Rule{
		Name:      raw.Name,
		Endpoints: raw.Endpoints,
		Verdict:   raw.Verdict,
		Priority:  raw.Priority,
		Disabled:  raw.Disabled,
		Condition: raw.Condition,
		Reason:    raw.Reason,
		order:     raw.order,
	}
	switch raw.Endpoints[0].Kind {
	case "cidr":
		for _, endpoint := range raw.Endpoints {
			if _, ok := p.cidrEndpoints[endpoint.String()]; !ok {
				return fmt.Errorf("rule %q references unknown endpoint %q", raw.Name, endpoint.String())
			}
		}
		if raw.Condition != "" {
			return fmt.Errorf("rule %q condition is only supported for https endpoint rules", raw.Name)
		}
		p.cidrRules = append(p.cidrRules, rule)
	case "https":
		for _, endpoint := range raw.Endpoints {
			if _, ok := p.httpsEndpoints[endpoint.String()]; !ok {
				return fmt.Errorf("rule %q references unknown endpoint %q", raw.Name, endpoint.String())
			}
		}
		if raw.Condition != "" {
			program, err := compileCondition(raw.Condition)
			if err != nil {
				return fmt.Errorf("rule %q condition: %w", raw.Name, err)
			}
			rule.program = program
		}
		p.httpsRules = append(p.httpsRules, rule)
	default:
		return fmt.Errorf("rule %q references unsupported endpoint kind %q", raw.Name, raw.Endpoints[0].Kind)
	}
	return nil
}

func (p *Policy) sortRules() {
	sort.SliceStable(p.cidrRules, func(i, j int) bool {
		return p.cidrRules[i].Priority > p.cidrRules[j].Priority
	})
	sort.SliceStable(p.httpsRules, func(i, j int) bool {
		return p.httpsRules[i].Priority > p.httpsRules[j].Priority
	})
}

func validateEndpointFamily(refs []Ref) error {
	if len(refs) == 0 {
		return fmt.Errorf("requires at least one endpoint")
	}
	kind := refs[0].Kind
	for _, ref := range refs[1:] {
		if ref.Kind != kind {
			return fmt.Errorf("all endpoints in one rule must have the same kind")
		}
	}
	return nil
}
