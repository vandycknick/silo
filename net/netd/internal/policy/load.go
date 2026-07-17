package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/net/netd/internal/policy/hostmatch"
	packageregistry "github.com/vandycknick/silo/net/netd/internal/registry"
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
	return loadCanonicalSource(path, source)
}

func LoadReader(filename string, reader io.Reader) (*Policy, error) {
	source, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read policy source %s: %w", filename, err)
	}
	return loadCanonicalSource(filename, source)
}

func loadCanonicalSource(filename string, source []byte) (*Policy, error) {
	var raw struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(source, &raw); err == nil && !emptyMetadata(raw.Metadata) {
		trimmedMetadata := bytes.TrimSpace(raw.Metadata)
		if !bytes.HasPrefix(trimmedMetadata, []byte("{")) {
			return nil, &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: "Invalid metadata", Detail: "metadata must be a JSON object", File: filename, Line: 1, Column: 1}}}
		}
		var metadata map[string]any
		if err := json.Unmarshal(trimmedMetadata, &metadata); err != nil {
			return nil, &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: "Invalid metadata", Detail: "metadata must be a JSON object", File: filename, Line: 1, Column: 1}}}
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var document networkPolicyFile
	if err := decoder.Decode(&document); err != nil {
		return nil, &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: "Invalid policy JSON", Detail: err.Error(), File: filename, Line: 1, Column: 1}}}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: "Invalid policy JSON", Detail: "policy file must contain exactly one JSON document", File: filename, Line: 1, Column: 1}}}
	}
	return compileNetworkPolicy(filename, document)
}

func compileNetworkPolicy(filename string, document networkPolicyFile) (*Policy, error) {
	if document.Version != 1 {
		return nil, compileLoadError(filename, "Unsupported policy version", fmt.Sprintf("policy version must be 1, got %d", document.Version))
	}
	compiled := newPolicy()
	compiled.metadata = document.metadataCopy()
	if document.Settings.DefaultAction != "" {
		compiled.DefaultAction = document.Settings.DefaultAction
	}
	if compiled.DefaultAction != ActionAllow && compiled.DefaultAction != ActionDeny {
		return nil, compileLoadError(filename, "Invalid settings", fmt.Sprintf("unsupported default_action %q", compiled.DefaultAction))
	}
	if document.Settings.Audit.BodyBufferBytes > 0 && document.Settings.Audit.BodyStorageBytes > 0 && document.Settings.Audit.BodyBufferBytes < document.Settings.Audit.BodyStorageBytes {
		compiled.diagnostics = append(compiled.diagnostics, Diagnostic{Severity: "warning", Summary: "Audit body buffer is smaller than storage sample", Detail: "body_buffer_bytes is smaller than body_storage_bytes; response/request bodies may truncate before the configured stored sample size", File: filename, Line: 1, Column: 1})
	}
	for _, endpoint := range document.Endpoints {
		if err := compiled.addEndpointDecl(endpoint); err != nil {
			return nil, compileLoadError(filename, "Invalid endpoint", err.Error())
		}
	}
	for _, tunnel := range document.Tailscale {
		if tunnel.Name == "" {
			return nil, compileLoadError(filename, "Invalid tailscale tunnel", "name is required")
		}
		if _, ok := compiled.tailscaleByName[tunnel.Name]; ok {
			return nil, compileLoadError(filename, "Invalid tailscale tunnel", fmt.Sprintf("duplicate tailscale tunnel %q", tunnel.Name))
		}
		compiled.tailscaleByName[tunnel.Name] = struct{}{}
	}
	for _, credential := range document.Credentials {
		if err := compiled.addCredentialDecl(credential); err != nil {
			return nil, compileLoadError(filename, "Invalid credential", err.Error())
		}
	}
	for index, rule := range document.Rules {
		if err := compiled.addRuleDecl(rule, index); err != nil {
			return nil, compileLoadError(filename, "Invalid rule", err.Error())
		}
	}
	for _, forward := range document.Forwards {
		if forward.Name == "" {
			return nil, compileLoadError(filename, "Invalid forward", "name is required")
		}
		if forward.Kind != "host" && forward.Kind != "tailscale" {
			return nil, compileLoadError(filename, "Invalid forward", fmt.Sprintf("unsupported forward kind %q", forward.Kind))
		}
		if forward.Kind == "tailscale" {
			if forward.Tunnel == "" {
				return nil, compileLoadError(filename, "Invalid forward", fmt.Sprintf("tailscale forward %q requires tunnel", forward.Name))
			}
			if _, ok := compiled.tailscaleByName[forward.Tunnel]; !ok {
				return nil, compileLoadError(filename, "Invalid forward", fmt.Sprintf("forward %q references unknown tailscale tunnel %q", forward.Name, forward.Tunnel))
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
	if decl.Name == "" {
		return fmt.Errorf("name is required")
	}
	if _, ok := p.endpointRefsByName[decl.Name]; ok {
		return fmt.Errorf("duplicate endpoint name %q", decl.Name)
	}
	definition, ok := p.registry.Endpoint(decl.Kind)
	if !ok {
		return fmt.Errorf("unsupported endpoint kind %q", decl.Kind)
	}
	if err := p.validateEndpointDescriptor(decl, definition); err != nil {
		return err
	}
	switch definition.Schema {
	case EndpointSchemaIP:
		if _, ok := p.ipEndpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileIPEndpoint(decl.Name, rawIPEndpoint{Source: decl.SourceCIDRs, Destination: decl.DestinationCIDRs, Protocol: decl.Protocol, Ports: decl.Ports})
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		p.ipEndpoints[key] = endpoint
	case EndpointSchemaHosts:
		endpoints, err := p.httpEndpointsForTransport(definition.Transport)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		if _, ok := endpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileHTTPEndpointDecl(definition, decl.Name, decl.Hosts)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		if err := p.addHTTPEndpoint(endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		endpoints[key] = endpoint
	case EndpointSchemaRegistries:
		if _, ok := p.registryEndpoints[key]; ok {
			return fmt.Errorf("Endpoint %q is already defined.", key)
		}
		endpoint, err := compileRegistryEndpointDecl(definition, decl)
		if err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		if err := p.addHTTPEndpoint(endpoint.Endpoint); err != nil {
			return fmt.Errorf("decode endpoint %q: %v", key, err)
		}
		p.packageEndpoints[key] = endpoint.Endpoint
		p.registryEndpoints[key] = endpoint
	default:
		return fmt.Errorf("endpoint kind %q has unsupported schema %q", decl.Kind, definition.Schema)
	}
	p.endpointRefsByName[decl.Name] = ref
	p.endpointDefinitions[key] = definition
	return nil
}

func (p *Policy) validateEndpointDescriptor(decl EndpointDecl, definition EndpointDefinition) error {
	if decl.Family != definition.Family {
		return fmt.Errorf("endpoint %q type %q requires family %q", decl.Name, decl.Kind, definition.Family)
	}
	if decl.Transport != definition.Transport {
		return fmt.Errorf("endpoint %q type %q requires transport %q", decl.Name, decl.Kind, definition.Transport)
	}
	if decl.TLS != definition.TLSMode {
		return fmt.Errorf("endpoint %q type %q requires TLS mode %q", decl.Name, decl.Kind, definition.TLSMode)
	}
	expectedCapabilities := []string(nil)
	if definition.SupportsCredentials {
		expectedCapabilities = []string{"credential-injection"}
	}
	if !slices.Equal(decl.Capabilities, expectedCapabilities) {
		return fmt.Errorf("endpoint %q type %q has unexpected capabilities", decl.Name, decl.Kind)
	}
	return nil
}

func compileRegistryEndpointDecl(definition EndpointDefinition, decl EndpointDecl) (*RegistryEndpoint, error) {
	if len(decl.Config) < 2 || len(decl.Config) > 3 {
		return nil, fmt.Errorf("canonical config must contain registries, malware_feed, and optional filter_package_age")
	}
	rawRegistries, ok := decl.Config["registries"].([]any)
	if !ok || len(rawRegistries) == 0 {
		return nil, fmt.Errorf("registries must be a non-empty array")
	}
	registries := make([]string, 0, len(rawRegistries))
	seen := make(map[string]struct{}, len(rawRegistries))
	for _, rawRegistry := range rawRegistries {
		registry, ok := rawRegistry.(string)
		if !ok {
			return nil, fmt.Errorf("registry names must be npm or pypi")
		}
		if _, err := packageregistry.NewCatalog([]string{registry}); err != nil {
			return nil, fmt.Errorf("registry names must be npm or pypi")
		}
		if _, ok := seen[registry]; ok {
			return nil, fmt.Errorf("registry %q is declared more than once", registry)
		}
		seen[registry] = struct{}{}
		registries = append(registries, registry)
	}
	if !slices.Equal(decl.Hosts, registryHosts(registries)) {
		return nil, fmt.Errorf("registry host bindings do not match registries")
	}
	baseURL, ok := decl.Config["malware_feed"].(string)
	if !ok {
		return nil, fmt.Errorf("malware_feed must be an HTTPS URL")
	}
	host, port, ok := parseHTTPSOrigin(baseURL)
	if !ok {
		return nil, fmt.Errorf("malware_feed must be an HTTPS URL with a valid host and optional port")
	}
	expectedEgress := []EgressDecl{{Host: host, Port: port, TLS: true}}
	if !slices.Equal(decl.Egress, expectedEgress) {
		return nil, fmt.Errorf("registry intelligence egress does not match malware_feed")
	}
	var filterPackageAge uint32
	if rawAge, exists := decl.Config["filter_package_age"]; exists {
		age, ok := rawAge.(float64)
		if !ok || age < 1 || age > float64(^uint32(0)) || age != float64(uint32(age)) {
			return nil, fmt.Errorf("filter_package_age must be a positive integer")
		}
		filterPackageAge = uint32(age)
	}
	expectedConfigKeys := 2
	if filterPackageAge > 0 {
		expectedConfigKeys++
	}
	if len(decl.Config) != expectedConfigKeys {
		return nil, fmt.Errorf("canonical config must contain registries, malware_feed, and optional filter_package_age")
	}
	endpoint, err := compileHTTPEndpointDecl(definition, decl.Name, decl.Hosts)
	if err != nil {
		return nil, err
	}
	return &RegistryEndpoint{
		Endpoint:         endpoint,
		Registries:       registries,
		MalwareFeed:      baseURL,
		FilterPackageAge: filterPackageAge,
		Egress:           expectedEgress[0],
	}, nil
}

func registryHosts(registries []string) []string {
	hosts, _ := packageregistry.HostsForNames(registries)
	return hosts
}

func parseHTTPSOrigin(value string) (string, uint16, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", 0, false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || strings.IndexFunc(host, func(character rune) bool {
		return character == ' ' || character == '\t' || character == '\n' || character == '\r'
	}) >= 0 {
		return "", 0, false
	}
	port := uint64(443)
	if parsed.Port() != "" {
		parsedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || parsedPort == 0 {
			return "", 0, false
		}
		port = parsedPort
	}
	return host, uint16(port), true
}

func (p *Policy) httpEndpointsForTransport(transport Transport) (map[string]*HTTPEndpoint, error) {
	switch transport {
	case TransportHTTPProxy:
		return p.httpEndpoints, nil
	case TransportHTTPSMITM:
		return p.httpsEndpoints, nil
	case TransportTLSTerminate:
		return p.packageEndpoints, nil
	default:
		return nil, fmt.Errorf("transport %q does not use the HTTP endpoint frontend", transport)
	}
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

func compileHTTPEndpointDecl(definition EndpointDefinition, name string, hosts []string) (*HTTPEndpoint, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("Missing hosts: hosts is required")
	}
	endpoint := &HTTPEndpoint{Kind: definition.Kind, Name: name, Family: definition.Family, Transport: definition.Transport, DefaultPort: definition.DefaultPort}
	seen := make(map[string]struct{})
	for _, host := range hosts {
		binding, err := hostmatch.ParseBinding(host, definition.DefaultPort)
		if err != nil {
			return nil, err
		}
		key := hostBindingKey(definition.Transport, binding.Host, binding.Port, binding.Wildcard)
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
	if decl.Name == "" {
		return fmt.Errorf("name is required")
	}
	if _, ok := p.credentialRefsByName[decl.Name]; ok {
		return fmt.Errorf("duplicate credential name %q", decl.Name)
	}
	endpoint, ok := p.endpointRefsByName[decl.Endpoint]
	if !ok {
		return fmt.Errorf("credential %q.%q references unknown endpoint %q", decl.Kind, decl.Name, decl.Endpoint)
	}
	definition, ok := p.endpointDefinitions[endpoint.String()]
	if !ok || !definition.SupportsCredentials {
		return fmt.Errorf("credential %q.%q must reference an https endpoint", decl.Kind, decl.Name)
	}
	key := Ref{Kind: decl.Kind, Name: decl.Name}.String()
	if _, ok := p.credentials[key]; ok {
		return fmt.Errorf("duplicate credential %q", key)
	}
	credential := &Credential{
		Kind:           decl.Kind,
		Name:           decl.Name,
		Endpoint:       endpoint,
		Username:       decl.Username,
		Header:         decl.Header,
		Prefix:         decl.Prefix,
		IdempotencyKey: decl.IdempotencyKey,
		policy:         p,
	}
	if decl.Condition != "" {
		condition, err := compileCondition(p.registry, EndpointFamilyHTTP, decl.Condition)
		if err != nil {
			return fmt.Errorf("credential %q.%q condition is invalid: %w", decl.Kind, decl.Name, err)
		}
		credential.Condition = decl.Condition
		credential.condition = condition
	}
	p.credentials[key] = credential
	p.credentialRefsByName[decl.Name] = Ref{Kind: decl.Kind, Name: decl.Name}
	p.credentialsByEndpoint[endpoint.String()] = append(p.credentialsByEndpoint[endpoint.String()], credential)
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

func (p *Policy) addRuleDecl(decl RuleDecl, order int) error {
	endpoints := make([]Ref, 0, len(decl.Endpoints))
	for _, name := range decl.Endpoints {
		endpoint, ok := p.endpointRefsByName[name]
		if !ok {
			return fmt.Errorf("rule %q references unknown endpoint %q", decl.Name, name)
		}
		endpoints = append(endpoints, endpoint)
	}
	family, err := p.validateEndpointFamily(endpoints)
	if err != nil {
		return fmt.Errorf("rule %q: %w", decl.Name, err)
	}
	var credentialRef *Ref
	if decl.Credential != "" {
		credential, ok := p.credentialRefsByName[decl.Credential]
		if !ok {
			return fmt.Errorf("rule %q references unknown credential %q", decl.Name, decl.Credential)
		}
		credentialRef = &credential
	}
	if decl.Tunnel != "" {
		if _, ok := p.tailscaleByName[decl.Tunnel]; !ok {
			return fmt.Errorf("rule %q references unknown tailscale tunnel %q", decl.Name, decl.Tunnel)
		}
		if decl.Verdict != ActionAllow {
			return fmt.Errorf("rule %q tunnel is only valid on allow rules", decl.Name)
		}
	}
	if decl.Verdict != ActionAllow && decl.Verdict != ActionDeny {
		return fmt.Errorf("rule %q has unsupported verdict %q", decl.Name, decl.Verdict)
	}
	rule := &Rule{
		Name:       decl.Name,
		Family:     family,
		Endpoints:  endpoints,
		Credential: credentialRef,
		Verdict:    decl.Verdict,
		Priority:   decl.Priority,
		Disabled:   decl.Disabled,
		Reason:     decl.Reason,
		order:      order,
		policy:     p,
	}
	if decl.Condition != "" {
		condition, err := compileCondition(p.registry, family, decl.Condition)
		if err != nil {
			return fmt.Errorf("rule %q condition is invalid: %w", decl.Name, err)
		}
		rule.Condition = decl.Condition
		rule.condition = condition
	}
	if err := p.validateRuleCredential(rule); err != nil {
		return err
	}
	familyDefinition, ok := p.registry.Family(family)
	if !ok {
		return fmt.Errorf("rule %q references unsupported endpoint family %q", decl.Name, family)
	}
	if familyDefinition.Condition == ConditionKindNone && rule.condition != nil {
		return fmt.Errorf("rule %q condition is only supported for HTTP-family endpoint rules", decl.Name)
	}
	if rule.Disabled {
		return nil
	}
	p.rulesByFamily[family] = append(p.rulesByFamily[family], rule)
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
	definition, ok := p.endpointDefinitions[credential.Endpoint.String()]
	if !ok || !definition.SupportsCredentials {
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
	for family := range p.rulesByFamily {
		rules := p.rulesByFamily[family]
		sort.SliceStable(rules, func(i, j int) bool {
			return rules[i].Priority > rules[j].Priority
		})
	}
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
	definition, ok := p.endpointDefinitions[ref.String()]
	if !ok {
		return "", fmt.Errorf("references unknown endpoint %q", ref.String())
	}
	return definition.Family, nil
}
