package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy/hostmatch"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy/native"
)

type LoadError struct {
	Filename    string       `json:"filename"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func (e *LoadError) Error() string {
	if e == nil {
		return ""
	}
	count := 0
	for _, diagnostic := range e.Diagnostics {
		if diagnostic.Severity == "error" {
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
		if diagnostic.Severity != "error" {
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

func diagnosticLocation(fallback string, diagnostic Diagnostic) string {
	file := diagnostic.File
	if file == "" {
		file = fallback
	}
	if diagnostic.Line > 0 && diagnostic.Column > 0 {
		return fmt.Sprintf("%s:%d:%d", file, diagnostic.Line, diagnostic.Column)
	}
	return file
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
	nativePolicy, status, errorJSON, err := native.ParseSource(filename, source)
	if err != nil {
		return nil, err
	}
	if status == native.StatusLoadError {
		return nil, decodeLoadError(filename, errorJSON)
	}
	if status != native.StatusOK {
		return nil, fmt.Errorf("parse policy source %s failed with status %d: %s", filename, status, string(errorJSON))
	}

	snapshotJSON, err := nativePolicy.SnapshotJSON()
	if err != nil {
		nativePolicy.Close()
		return nil, err
	}
	var snapshot policySnapshot
	if err := json.Unmarshal(snapshotJSON, &snapshot); err != nil {
		nativePolicy.Close()
		return nil, fmt.Errorf("decode policy snapshot: %w", err)
	}
	compiled, err := compileSnapshot(filename, snapshot, nativePolicy)
	if err != nil {
		nativePolicy.Close()
		return nil, err
	}
	return compiled, nil
}

func decodeLoadError(filename string, payload []byte) error {
	var loadErr LoadError
	if err := json.Unmarshal(payload, &loadErr); err != nil || len(loadErr.Diagnostics) == 0 {
		return &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: "Invalid policy", Detail: string(payload), File: filename, Line: 1, Column: 1}}}
	}
	if loadErr.Filename == "" {
		loadErr.Filename = filename
	}
	return &loadErr
}

func compileSnapshot(filename string, snapshot policySnapshot, nativePolicy *native.Policy) (*Policy, error) {
	compiled := Default()
	compiled.native = nativePolicy
	compiled.Documents = snapshot.Documents
	compiled.diagnostics = append(compiled.diagnostics, snapshot.Diagnostics...)
	if len(snapshot.Documents) == 0 {
		return compiled, nil
	}
	for _, document := range snapshot.Documents {
		compiled.DefaultAction = document.Settings.DefaultAction
		for _, endpoint := range document.Endpoints {
			if err := compiled.addEndpointDecl(endpoint); err != nil {
				return nil, compileLoadError(filename, "Invalid endpoint", err.Error())
			}
		}
		for _, credential := range document.Credentials {
			if err := compiled.addCredentialDecl(credential); err != nil {
				return nil, compileLoadError(filename, "Invalid credential", err.Error())
			}
		}
		for _, rule := range document.Rules {
			if err := compiled.addRuleDecl(rule); err != nil {
				return nil, compileLoadError(filename, "Invalid rule", err.Error())
			}
		}
	}
	compiled.sortRules()
	return compiled, nil
}

func compileLoadError(filename string, summary string, detail string) error {
	return &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: summary, Detail: detail, File: filename, Line: 1, Column: 1}}}
}

type rawIPEndpoint struct {
	Source      []string
	Destination []string
	Protocol    string
	Ports       []PortRange
}

func (p *Policy) addEndpointDecl(decl EndpointDecl) error {
	ref := Ref{Kind: decl.Kind, Name: decl.Name}
	key := ref.String()
	switch decl.Kind {
	case "ip":
		if _, ok := p.ipEndpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileIPEndpoint(decl.Name, rawIPEndpoint{Source: decl.Source, Destination: decl.Destination, Protocol: decl.Protocol, Ports: decl.Ports})
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		p.ipEndpoints[key] = endpoint
	case "http":
		if _, ok := p.httpEndpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileHTTPEndpointDecl(decl.Kind, decl.Name, TransportHTTPProxy, 80, decl.Hosts)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		if err := p.addHTTPEndpoint(endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		p.httpEndpoints[key] = endpoint
	case "https":
		if _, ok := p.httpsEndpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileHTTPEndpointDecl(decl.Kind, decl.Name, TransportHTTPSMITM, 443, decl.Hosts)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		if err := p.addHTTPEndpoint(endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		p.httpsEndpoints[key] = endpoint
	default:
		return fmt.Errorf("unsupported endpoint kind %q", decl.Kind)
	}
	return nil
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
	sort.Slice(normalized, func(i, j int) bool {
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

func compileHTTPEndpointDecl(kind string, name string, transport Transport, defaultPort uint16, hosts []string) (*HTTPEndpoint, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts is required")
	}
	endpoint := &HTTPEndpoint{Kind: kind, Name: name, Family: EndpointFamilyHTTP, Transport: transport, DefaultPort: defaultPort}
	seen := make(map[string]struct{})
	for _, host := range hosts {
		binding, err := hostmatch.ParseBinding(host, defaultPort)
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

func (p *Policy) addCredentialDecl(decl CredentialDecl) error {
	if !knownCredentialKind(decl.Kind) {
		return fmt.Errorf("unsupported credential kind %q", decl.Kind)
	}
	if decl.Endpoint.Kind != "https" {
		return fmt.Errorf("credential %q.%q must reference an https endpoint", decl.Kind, decl.Name)
	}
	if _, ok := p.httpsEndpoints[decl.Endpoint.String()]; !ok {
		return fmt.Errorf("credential %q.%q references unknown endpoint %q", decl.Kind, decl.Name, decl.Endpoint.String())
	}
	key := Ref{Kind: decl.Kind, Name: decl.Name}.String()
	if _, ok := p.credentials[key]; ok {
		return fmt.Errorf("duplicate credential %q", key)
	}
	credential := &Credential{Kind: decl.Kind, Name: decl.Name, Endpoint: decl.Endpoint, policy: p}
	if decl.Condition != nil {
		credential.Condition = decl.Condition.Source
		credential.condition = &httpCondition{id: decl.Condition.ID}
	}
	p.credentials[key] = credential
	p.credentialsByEndpoint[decl.Endpoint.String()] = append(p.credentialsByEndpoint[decl.Endpoint.String()], credential)
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

func (p *Policy) addRuleDecl(decl RuleDecl) error {
	family, err := p.validateEndpointFamily(decl.Endpoints)
	if err != nil {
		return fmt.Errorf("rule %q: %w", decl.Name, err)
	}
	rule := &Rule{
		Name:       decl.Name,
		Family:     family,
		Endpoints:  decl.Endpoints,
		Credential: decl.Credential,
		Verdict:    decl.Verdict,
		Priority:   decl.Priority,
		Disabled:   decl.Disabled,
		Reason:     decl.Reason,
		order:      decl.Order,
		policy:     p,
	}
	if decl.Condition != nil {
		rule.Condition = decl.Condition.Source
		rule.condition = &httpCondition{id: decl.Condition.ID}
	}
	if err := p.validateRuleCredential(rule); err != nil {
		return err
	}
	switch family {
	case EndpointFamilyIP:
		if rule.condition != nil {
			return fmt.Errorf("rule %q condition is only supported for HTTP-family endpoint rules", decl.Name)
		}
		if rule.Disabled {
			return nil
		}
		p.ipRules = append(p.ipRules, rule)
	case EndpointFamilyHTTP:
		if rule.Disabled {
			return nil
		}
		p.httpRules = append(p.httpRules, rule)
	default:
		return fmt.Errorf("rule %q references unsupported endpoint family %q", decl.Name, family)
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
