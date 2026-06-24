package policy

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy/hostmatch"
)

type LoadError struct {
	Filename    string
	Diagnostics hcl.Diagnostics
}

func (e *LoadError) Error() string {
	if e == nil {
		return ""
	}
	count := 0
	for _, diagnostic := range e.Diagnostics {
		if diagnostic.Severity == hcl.DiagError {
			count++
		}
	}
	var builder strings.Builder
	if count == 1 {
		fmt.Fprintf(&builder, "load policy file %s failed with 1 error:", e.Filename)
	} else {
		fmt.Fprintf(&builder, "load policy file %s failed with %d errors:", e.Filename, count)
	}
	for _, diagnostic := range e.Diagnostics {
		if diagnostic.Severity != hcl.DiagError {
			continue
		}
		fmt.Fprintf(&builder, "\n%s: %s", diagnosticLocation(e.Filename, diagnostic), diagnostic.Summary)
		if diagnostic.Detail == "" {
			continue
		}
		for _, line := range strings.Split(diagnostic.Detail, "\n") {
			fmt.Fprintf(&builder, "\n  %s", line)
		}
	}
	return builder.String()
}

func diagnosticLocation(fallback string, diagnostic *hcl.Diagnostic) string {
	if diagnostic != nil && diagnostic.Subject != nil && diagnostic.Subject.Filename != "" {
		if diagnostic.Subject.Start.Line > 0 && diagnostic.Subject.Start.Column > 0 {
			return fmt.Sprintf("%s:%d:%d", diagnostic.Subject.Filename, diagnostic.Subject.Start.Line, diagnostic.Subject.Start.Column)
		}
		return diagnostic.Subject.Filename
	}
	return fallback
}

func LoadFile(path string) (*Policy, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	return loadSource(path, source)
}

func LoadReader(filename string, reader io.Reader) (*Policy, error) {
	source, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read policy source %s: %w", filename, err)
	}
	return loadSource(filename, source)
}

func loadSource(filename string, source []byte) (*Policy, error) {
	parser := hclparse.NewParser()
	file, diagnostics := parser.ParseHCL(source, filename)
	if diagnostics.HasErrors() {
		return nil, &LoadError{Filename: filename, Diagnostics: diagnostics}
	}
	compiled, diagnostics := loadBody(file.Body)
	if diagnostics.HasErrors() {
		return nil, &LoadError{Filename: filename, Diagnostics: diagnostics}
	}
	return compiled, nil
}

func loadBody(body hcl.Body) (*Policy, hcl.Diagnostics) {
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

	compiled := Default()
	if content == nil {
		return nil, diagnostics
	}
	rawCredentials := make([]rawCredential, 0)
	rawRules := make([]rawRule, 0)
	seenRules := make(map[string]struct{})
	settingsSeen := false

	for _, block := range content.Blocks {
		switch block.Type {
		case "settings":
			if settingsSeen {
				diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Duplicate settings block", "Only one settings block is allowed."))
				continue
			}
			settingsSeen = true
			diagnostics = append(diagnostics, decodeSettings(compiled, block)...)
		case "endpoint":
			diagnostics = append(diagnostics, decodeEndpoint(compiled, block)...)
		case "credential":
			credential, credentialDiagnostics := decodeCredential(block)
			diagnostics = append(diagnostics, credentialDiagnostics...)
			if !credentialDiagnostics.HasErrors() {
				rawCredentials = append(rawCredentials, credential)
			}
		case "tailscale", "forward":
			diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Reserved policy block", fmt.Sprintf("%s blocks are reserved by the policy schema but not implemented by bento-netd yet", block.Type)))
		case "rule":
			name := block.Labels[0]
			if _, ok := seenRules[name]; ok {
				diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Duplicate rule", fmt.Sprintf("Rule %q is already defined.", name)))
				continue
			}
			seenRules[name] = struct{}{}
			rule, ruleDiagnostics := decodeRule(block, len(rawRules))
			diagnostics = append(diagnostics, ruleDiagnostics...)
			if !ruleDiagnostics.HasErrors() {
				rawRules = append(rawRules, rule)
			}
		}
	}

	for _, credential := range rawCredentials {
		if err := compiled.addCredential(credential); err != nil {
			diagnostics = append(diagnostics, loadDiagnostic(credential.Subject, "Invalid credential", err.Error()))
		}
	}
	for _, rule := range rawRules {
		if err := compiled.addRule(rule); err != nil {
			diagnostics = append(diagnostics, loadDiagnostic(rule.Subject, "Invalid rule", err.Error()))
		}
	}
	if diagnostics.HasErrors() {
		return nil, diagnostics
	}
	compiled.sortRules()
	return compiled, diagnostics
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
	Subject   hcl.Range
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
	Subject    hcl.Range
}

func decodeSettings(policy *Policy, block *hcl.Block) hcl.Diagnostics {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "default_action"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "audit"}},
	})
	if content == nil {
		return diagnostics
	}
	if attr, ok := content.Attributes["default_action"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.default_action", err.Error()))
		} else if action, err := parseTerminalAction(value); err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.default_action", err.Error()))
		} else {
			policy.DefaultAction = action
		}
	}
	auditSeen := false
	for _, auditBlock := range content.Blocks {
		if auditSeen {
			diagnostics = append(diagnostics, loadDiagnostic(auditBlock.DefRange, "Duplicate settings.audit block", "Only one settings.audit block is allowed."))
			continue
		}
		auditSeen = true
		diagnostics = append(diagnostics, decodeAuditSettings(policy, auditBlock)...)
	}
	return diagnostics
}

func decodeAuditSettings(policy *Policy, block *hcl.Block) hcl.Diagnostics {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "body_buffer"},
		{Name: "body_storage"},
	}})
	if content == nil {
		return diagnostics
	}
	bodyBuffer := int64(1024 * 1024)
	bodyStorage := int64(4 * 1024)
	if attr, ok := content.Attributes["body_buffer"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.audit.body_buffer", err.Error()))
		} else if parsed, err := parseSize(value); err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.audit.body_buffer", err.Error()))
		} else {
			bodyBuffer = parsed
		}
	}
	if attr, ok := content.Attributes["body_storage"]; ok {
		value, err := decodeStringAttr(attr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.audit.body_storage", err.Error()))
		} else if parsed, err := parseSize(value); err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid settings.audit.body_storage", err.Error()))
		} else {
			bodyStorage = parsed
		}
	}
	if !diagnostics.HasErrors() && bodyBuffer < bodyStorage {
		policy.addWarning("settings.audit.body_buffer is smaller than settings.audit.body_storage")
	}
	return diagnostics
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

func decodeEndpoint(policy *Policy, block *hcl.Block) hcl.Diagnostics {
	var diagnostics hcl.Diagnostics
	kind := block.Labels[0]
	name := block.Labels[1]
	if !hclsyntax.ValidIdentifier(name) {
		return append(diagnostics, loadDiagnostic(labelRange(block, 1), "Invalid endpoint name", fmt.Sprintf("endpoint %q.%q name must use a traversal identifier", kind, name)))
	}
	ref := Ref{Kind: kind, Name: name}
	key := ref.String()
	switch kind {
	case "ip":
		if _, ok := policy.ipEndpoints[key]; ok {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Duplicate endpoint", fmt.Sprintf("Endpoint %q is already defined.", key)))
		}
		raw, endpointDiagnostics := decodeIPEndpoint(block)
		diagnostics = append(diagnostics, endpointDiagnostics...)
		if endpointDiagnostics.HasErrors() {
			return diagnostics
		}
		endpoint, err := compileIPEndpoint(name, raw)
		if err != nil {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Invalid endpoint", fmt.Sprintf("decode endpoint %q: %v", key, err)))
		}
		policy.ipEndpoints[key] = endpoint
	case "http":
		if _, ok := policy.httpEndpoints[key]; ok {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Duplicate endpoint", fmt.Sprintf("Endpoint %q is already defined.", key)))
		}
		endpoint, endpointDiagnostics := decodeHTTPEndpoint(kind, name, TransportHTTPProxy, 80, block)
		diagnostics = append(diagnostics, endpointDiagnostics...)
		if endpointDiagnostics.HasErrors() {
			return diagnostics
		}
		if err := policy.addHTTPEndpoint(endpoint); err != nil {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Invalid endpoint", fmt.Sprintf("decode endpoint %q: %v", key, err)))
		}
		policy.httpEndpoints[key] = endpoint
	case "https":
		if _, ok := policy.httpsEndpoints[key]; ok {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Duplicate endpoint", fmt.Sprintf("Endpoint %q is already defined.", key)))
		}
		endpoint, endpointDiagnostics := decodeHTTPEndpoint(kind, name, TransportHTTPSMITM, 443, block)
		diagnostics = append(diagnostics, endpointDiagnostics...)
		if endpointDiagnostics.HasErrors() {
			return diagnostics
		}
		if err := policy.addHTTPEndpoint(endpoint); err != nil {
			return append(diagnostics, loadDiagnostic(block.DefRange, "Invalid endpoint", fmt.Sprintf("decode endpoint %q: %v", key, err)))
		}
		policy.httpsEndpoints[key] = endpoint
	default:
		diagnostics = append(diagnostics, loadDiagnostic(labelRange(block, 0), "Unsupported endpoint kind", fmt.Sprintf("unsupported endpoint kind %q", kind)))
	}
	return diagnostics
}

func decodeIPEndpoint(block *hcl.Block) (rawIPEndpoint, hcl.Diagnostics) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "source"},
		{Name: "destination"},
		{Name: "protocol"},
		{Name: "ports"},
	}})
	raw := rawIPEndpoint{Protocol: "any"}
	if content == nil {
		return raw, diagnostics
	}
	if attr, ok := content.Attributes["source"]; ok {
		var source []string
		if sourceDiagnostics := gohcl.DecodeExpression(attr.Expr, nil, &source); sourceDiagnostics.HasErrors() {
			diagnostics = append(diagnostics, sourceDiagnostics...)
		} else {
			raw.Source = source
		}
	}
	if attr, ok := content.Attributes["destination"]; ok {
		var destination []string
		if destinationDiagnostics := gohcl.DecodeExpression(attr.Expr, nil, &destination); destinationDiagnostics.HasErrors() {
			diagnostics = append(diagnostics, destinationDiagnostics...)
		} else {
			raw.Destination = destination
		}
	}
	if attr, ok := content.Attributes["protocol"]; ok {
		protocol, err := decodeStringAttr(attr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid endpoint protocol", err.Error()))
		} else {
			raw.Protocol = protocol
		}
	}
	if attr, ok := content.Attributes["ports"]; ok {
		ports, err := decodePortRangesAttr(attr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(attr, "Invalid endpoint ports", err.Error()))
		} else {
			raw.Ports = ports
		}
	}
	return raw, diagnostics
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
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	endpoint := &IPEndpoint{Name: name, Protocol: protocol, Ports: normalizePortRanges(raw.Ports)}
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

func normalizePortRanges(ranges []PortRange) []PortRange {
	if len(ranges) == 0 {
		return nil
	}
	normalized := make([]PortRange, len(ranges))
	copy(normalized, ranges)
	sort.Slice(normalized, func(i int, j int) bool {
		if normalized[i].Start == normalized[j].Start {
			return normalized[i].End < normalized[j].End
		}
		return normalized[i].Start < normalized[j].Start
	})
	merged := normalized[:0]
	for _, current := range normalized {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if uint32(current.Start) <= uint32(last.End)+1 {
			if current.End > last.End {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func decodeHTTPEndpoint(kind string, name string, transport Transport, defaultPort uint16, block *hcl.Block) (*HTTPEndpoint, hcl.Diagnostics) {
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "hosts"}}})
	if content == nil {
		return nil, diagnostics
	}
	hostsAttr, ok := content.Attributes["hosts"]
	if !ok {
		return nil, append(diagnostics, loadDiagnostic(block.DefRange, "Missing hosts", "hosts is required"))
	}
	var raw rawHTTPEndpoint
	if hostDiagnostics := gohcl.DecodeExpression(hostsAttr.Expr, nil, &raw.Hosts); hostDiagnostics.HasErrors() {
		return nil, append(diagnostics, hostDiagnostics...)
	}
	if len(raw.Hosts) == 0 {
		return nil, append(diagnostics, attrDiagnostic(hostsAttr, "Invalid hosts", "hosts must not be empty"))
	}
	endpoint := &HTTPEndpoint{Kind: kind, Name: name, Family: EndpointFamilyHTTP, Transport: transport, DefaultPort: defaultPort}
	seen := make(map[string]struct{})
	for _, host := range raw.Hosts {
		binding, err := hostmatch.ParseBinding(host, defaultPort)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(hostsAttr, "Invalid host binding", err.Error()))
			continue
		}
		key := hostBindingKey(transport, binding.Host, binding.Port, binding.Wildcard)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		endpoint.Hosts = append(endpoint.Hosts, binding)
	}
	if diagnostics.HasErrors() {
		return nil, diagnostics
	}
	return endpoint, diagnostics
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

func decodeCredential(block *hcl.Block) (rawCredential, hcl.Diagnostics) {
	raw := rawCredential{Kind: block.Labels[0], Name: block.Labels[1], Subject: block.DefRange}
	content, diagnostics := block.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{
		{Name: "endpoint"},
		{Name: "condition"},
	}})
	if content == nil {
		return raw, diagnostics
	}
	if !hclsyntax.ValidIdentifier(block.Labels[1]) {
		diagnostics = append(diagnostics, loadDiagnostic(labelRange(block, 1), "Invalid credential name", fmt.Sprintf("credential %q.%q name must use a traversal identifier", block.Labels[0], block.Labels[1])))
	}
	endpointAttr, ok := content.Attributes["endpoint"]
	if !ok {
		diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Missing credential endpoint", fmt.Sprintf("credential %q.%q requires endpoint", block.Labels[0], block.Labels[1])))
	} else if endpoint, err := decodeRefAttr(endpointAttr); err != nil {
		diagnostics = append(diagnostics, attrDiagnostic(endpointAttr, "Invalid credential endpoint", err.Error()))
	} else {
		raw.Endpoint = endpoint
	}
	if conditionAttr, ok := content.Attributes["condition"]; ok {
		decoded, err := decodeStringAttr(conditionAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(conditionAttr, "Invalid credential condition", err.Error()))
		} else {
			raw.Condition = decoded
		}
	}
	return raw, diagnostics
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

func decodeRule(block *hcl.Block, order int) (rawRule, hcl.Diagnostics) {
	rule := rawRule{Name: block.Labels[0], order: order, Subject: block.DefRange}
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
	if content == nil {
		return rule, diagnostics
	}
	if endpointAttr, ok := content.Attributes["endpoint"]; ok {
		if endpoint, err := decodeRefAttr(endpointAttr); err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(endpointAttr, "Invalid rule endpoint", err.Error()))
		} else {
			rule.Endpoints = append(rule.Endpoints, endpoint)
		}
	}
	if endpointsAttr, ok := content.Attributes["endpoints"]; ok {
		if len(rule.Endpoints) > 0 {
			diagnostics = append(diagnostics, attrDiagnostic(endpointsAttr, "Invalid rule endpoints", fmt.Sprintf("rule %q uses endpoint and endpoints", rule.Name)))
		} else if endpoints, err := decodeRefListAttr(endpointsAttr); err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(endpointsAttr, "Invalid rule endpoints", err.Error()))
		} else {
			rule.Endpoints = endpoints
		}
	}
	if len(rule.Endpoints) == 0 {
		diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Missing rule endpoint", fmt.Sprintf("rule %q requires endpoint or endpoints", rule.Name)))
	}
	verdictAttr, ok := content.Attributes["verdict"]
	if !ok {
		diagnostics = append(diagnostics, loadDiagnostic(block.DefRange, "Missing rule verdict", fmt.Sprintf("rule %q requires verdict", rule.Name)))
	} else if verdict, err := decodeStringAttr(verdictAttr); err != nil {
		diagnostics = append(diagnostics, attrDiagnostic(verdictAttr, "Invalid rule verdict", err.Error()))
	} else if action, err := parseRuleAction(verdict); err != nil {
		diagnostics = append(diagnostics, attrDiagnostic(verdictAttr, "Invalid rule verdict", err.Error()))
	} else {
		rule.Verdict = action
	}
	if credentialAttr, ok := content.Attributes["credential"]; ok {
		credential, err := decodeRefAttr(credentialAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(credentialAttr, "Invalid rule credential", err.Error()))
		} else {
			rule.Credential = &credential
		}
	}
	if conditionAttr, ok := content.Attributes["condition"]; ok {
		condition, err := decodeStringAttr(conditionAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(conditionAttr, "Invalid rule condition", err.Error()))
		} else {
			rule.Condition = condition
		}
	}
	if priorityAttr, ok := content.Attributes["priority"]; ok {
		priority, err := decodeIntAttr(priorityAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(priorityAttr, "Invalid rule priority", err.Error()))
		} else {
			rule.Priority = priority
		}
	}
	if disabledAttr, ok := content.Attributes["disabled"]; ok {
		disabled, err := decodeBoolAttr(disabledAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(disabledAttr, "Invalid rule disabled", err.Error()))
		} else {
			rule.Disabled = disabled
		}
	}
	if reasonAttr, ok := content.Attributes["reason"]; ok {
		reason, err := decodeStringAttr(reasonAttr)
		if err != nil {
			diagnostics = append(diagnostics, attrDiagnostic(reasonAttr, "Invalid rule reason", err.Error()))
		} else {
			rule.Reason = reason
		}
	}
	return rule, diagnostics
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

func loadDiagnostic(subject hcl.Range, summary string, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  summary,
		Detail:   detail,
		Subject:  &subject,
	}
}

func attrDiagnostic(attr *hcl.Attribute, summary string, detail string) *hcl.Diagnostic {
	if attr == nil {
		return &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail}
	}
	return loadDiagnostic(attr.Expr.Range(), summary, detail)
}

func labelRange(block *hcl.Block, index int) hcl.Range {
	if block != nil && index >= 0 && index < len(block.LabelRanges) {
		return block.LabelRanges[index]
	}
	if block != nil {
		return block.DefRange
	}
	return hcl.Range{}
}
