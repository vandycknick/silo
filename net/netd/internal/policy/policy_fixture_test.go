package policy

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type fixtureBlock struct {
	kind   string
	label1 string
	label2 string
	body   string
}

func loadLegacyHCLForTest(filename string, source []byte) (*Policy, error) {
	policy, err := parseFixturePolicy(filename, string(source))
	if err != nil {
		return nil, err
	}
	return compileNetworkPolicy(filename, policy)
}

func parseFixturePolicy(filename string, source string) (networkPolicyFile, error) {
	blocks, err := parseFixtureBlocks(source)
	if err != nil {
		return networkPolicyFile{}, fixtureLoadError(filename, "Invalid fixture", err.Error())
	}
	policy := networkPolicyFile{
		Version:  1,
		Metadata: map[string]any{},
		Settings: SettingsDecl{DefaultAction: ActionAllow},
	}
	for _, block := range blocks {
		switch block.kind {
		case "settings":
			settings, err := parseFixtureSettings(filename, block.body)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Settings = settings
		case "endpoint":
			endpoint, err := parseFixtureEndpoint(filename, block)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Endpoints = append(policy.Endpoints, endpoint)
		case "credential":
			credential, err := parseFixtureCredential(filename, block)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Credentials = append(policy.Credentials, credential)
		case "rule":
			rule, err := parseFixtureRule(filename, block)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Rules = append(policy.Rules, rule)
		case "tailscale":
			tunnel, err := parseFixtureTailscale(filename, block)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Tailscale = append(policy.Tailscale, tunnel)
		case "forward":
			forward, err := parseFixtureForward(filename, block)
			if err != nil {
				return networkPolicyFile{}, err
			}
			policy.Forwards = append(policy.Forwards, forward)
		default:
			return networkPolicyFile{}, fixtureLoadError(filename, "Unsupported block", fmt.Sprintf("unsupported top-level block %q", block.kind))
		}
	}
	return policy, nil
}

func parseFixtureBlocks(source string) ([]fixtureBlock, error) {
	var blocks []fixtureBlock
	for offset := 0; ; {
		offset = skipFixtureSpace(source, offset)
		if offset >= len(source) {
			return blocks, nil
		}
		kindStart := offset
		for offset < len(source) && (unicode.IsLetter(rune(source[offset])) || source[offset] == '_') {
			offset++
		}
		if kindStart == offset {
			return nil, fmt.Errorf("expected block kind near %q", source[offset:])
		}
		block := fixtureBlock{kind: source[kindStart:offset]}
		labels := []*string{&block.label1, &block.label2}
		for index := 0; index < len(labels); index++ {
			offset = skipFixtureSpace(source, offset)
			if offset >= len(source) || source[offset] != '"' {
				break
			}
			value, next, err := readFixtureQuoted(source, offset)
			if err != nil {
				return nil, err
			}
			*labels[index] = value
			offset = next
		}
		offset = skipFixtureSpace(source, offset)
		if offset >= len(source) || source[offset] != '{' {
			return nil, fmt.Errorf("expected block body for %s", block.kind)
		}
		bodyStart := offset + 1
		bodyEnd, err := findFixtureBlockEnd(source, offset)
		if err != nil {
			return nil, err
		}
		block.body = source[bodyStart:bodyEnd]
		blocks = append(blocks, block)
		offset = bodyEnd + 1
	}
}

func skipFixtureSpace(source string, offset int) int {
	for offset < len(source) {
		if unicode.IsSpace(rune(source[offset])) {
			offset++
			continue
		}
		if source[offset] == '#' {
			for offset < len(source) && source[offset] != '\n' {
				offset++
			}
			continue
		}
		break
	}
	return offset
}

func findFixtureBlockEnd(source string, open int) (int, error) {
	depth := 0
	inString := false
	escaped := false
	for offset := open; offset < len(source); offset++ {
		char := source[offset]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == '"' {
				inString = false
			}
			continue
		}
		switch char {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return offset, nil
			}
		}
	}
	return 0, fmt.Errorf("unterminated block")
}

func readFixtureQuoted(source string, offset int) (string, int, error) {
	end := offset + 1
	escaped := false
	for ; end < len(source); end++ {
		char := source[end]
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			value, err := strconv.Unquote(source[offset : end+1])
			return value, end + 1, err
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

func parseFixtureSettings(filename string, body string) (SettingsDecl, error) {
	settings := SettingsDecl{DefaultAction: ActionAllow}
	attrs := fixtureAttrs(removeNestedFixtureBlocks(body))
	if unknown := unknownFixtureAttrs(attrs, "default_action"); len(unknown) > 0 {
		return SettingsDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	if value, ok := attrs["default_action"]; ok {
		settings.DefaultAction = Action(mustFixtureString(filename, value))
	}
	for _, block := range nestedFixtureBlocks(body) {
		if block.kind != "audit" {
			return SettingsDecl{}, fixtureLoadError(filename, "Unsupported block", fmt.Sprintf("unsupported settings block %q", block.kind))
		}
		auditAttrs := fixtureAttrs(block.body)
		if unknown := unknownFixtureAttrs(auditAttrs, "body_buffer", "body_storage", "body_buffer_bytes", "body_storage_bytes"); len(unknown) > 0 {
			return SettingsDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
		}
		settings.Audit.BodyBufferBytes = fixtureSize(auditAttrs["body_buffer"])
		if settings.Audit.BodyBufferBytes == 0 {
			settings.Audit.BodyBufferBytes = fixtureSize(auditAttrs["body_buffer_bytes"])
		}
		settings.Audit.BodyStorageBytes = fixtureSize(auditAttrs["body_storage"])
		if settings.Audit.BodyStorageBytes == 0 {
			settings.Audit.BodyStorageBytes = fixtureSize(auditAttrs["body_storage_bytes"])
		}
	}
	return settings, nil
}

func parseFixtureEndpoint(filename string, block fixtureBlock) (EndpointDecl, error) {
	attrs := fixtureAttrs(block.body)
	if unknown := unknownFixtureAttrs(attrs, "source", "source_cidrs", "destination", "destination_cidrs", "protocol", "ports", "hosts"); len(unknown) > 0 {
		return EndpointDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	endpoint := EndpointDecl{Kind: block.label1, Name: block.label2, Protocol: "any"}
	endpoint.SourceCIDRs = fixtureStringList(attrs["source"])
	if len(endpoint.SourceCIDRs) == 0 {
		endpoint.SourceCIDRs = fixtureStringList(attrs["source_cidrs"])
	}
	endpoint.DestinationCIDRs = fixtureStringList(attrs["destination"])
	if len(endpoint.DestinationCIDRs) == 0 {
		endpoint.DestinationCIDRs = fixtureStringList(attrs["destination_cidrs"])
	}
	if value, ok := attrs["protocol"]; ok {
		endpoint.Protocol = mustFixtureString(filename, value)
	}
	if value, ok := attrs["ports"]; ok {
		ports, err := fixturePorts(filename, value)
		if err != nil {
			return EndpointDecl{}, err
		}
		endpoint.Ports = ports
	}
	endpoint.Hosts = fixtureStringList(attrs["hosts"])
	return endpoint, nil
}

func parseFixtureCredential(filename string, block fixtureBlock) (CredentialDecl, error) {
	attrs := fixtureAttrs(block.body)
	if unknown := unknownFixtureAttrs(attrs, "endpoint", "username", "header", "prefix", "idempotency_key", "condition"); len(unknown) > 0 {
		return CredentialDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	credential := CredentialDecl{Kind: block.label1, Name: block.label2}
	credential.Endpoint = fixtureRefName(attrs["endpoint"])
	credential.Username = fixtureOptionalString(filename, attrs["username"])
	credential.Header = fixtureOptionalString(filename, attrs["header"])
	credential.Prefix = fixtureOptionalString(filename, attrs["prefix"])
	credential.Condition = fixtureOptionalString(filename, attrs["condition"])
	if value, ok := attrs["idempotency_key"]; ok {
		credential.IdempotencyKey = strings.TrimSpace(value) == "true"
	}
	return credential, nil
}

func parseFixtureRule(filename string, block fixtureBlock) (RuleDecl, error) {
	attrs := fixtureAttrs(block.body)
	if unknown := unknownFixtureAttrs(attrs, "endpoint", "endpoints", "credential", "condition", "tunnel", "verdict", "priority", "disabled", "reason"); len(unknown) > 0 {
		return RuleDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	rule := RuleDecl{Name: block.label1, Verdict: ActionAllow}
	if value, ok := attrs["endpoint"]; ok {
		rule.Endpoints = append(rule.Endpoints, fixtureRefName(value))
	}
	for _, endpoint := range fixtureList(attrs["endpoints"]) {
		rule.Endpoints = append(rule.Endpoints, fixtureRefName(endpoint))
	}
	rule.Credential = fixtureRefName(attrs["credential"])
	rule.Condition = fixtureOptionalString(filename, attrs["condition"])
	rule.Tunnel = fixtureRefName(attrs["tunnel"])
	if value, ok := attrs["verdict"]; ok {
		rule.Verdict = Action(mustFixtureString(filename, value))
	}
	if value, ok := attrs["priority"]; ok {
		priority, _ := strconv.Atoi(strings.TrimSpace(value))
		rule.Priority = priority
	}
	if value, ok := attrs["disabled"]; ok {
		rule.Disabled = strings.TrimSpace(value) == "true"
	}
	rule.Reason = fixtureOptionalString(filename, attrs["reason"])
	return rule, nil
}

func parseFixtureTailscale(filename string, block fixtureBlock) (TailscaleDecl, error) {
	attrs := fixtureAttrs(block.body)
	if unknown := unknownFixtureAttrs(attrs, "tags", "hostname", "control_url"); len(unknown) > 0 {
		return TailscaleDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	return TailscaleDecl{Name: block.label1, Tags: fixtureStringList(attrs["tags"]), Hostname: fixtureOptionalString(filename, attrs["hostname"]), ControlURL: fixtureOptionalString(filename, attrs["control_url"])}, nil
}

func parseFixtureForward(filename string, block fixtureBlock) (NetworkForwardDecl, error) {
	attrs := fixtureAttrs(block.body)
	if unknown := unknownFixtureAttrs(attrs, "listen", "target", "target_port", "tunnel"); len(unknown) > 0 {
		return NetworkForwardDecl{}, fixtureLoadError(filename, "Unsupported argument", unsupportedFixtureArgumentDetail(unknown))
	}
	targetPort, _ := strconv.ParseUint(strings.TrimSpace(attrs["target_port"]), 10, 16)
	return NetworkForwardDecl{Name: block.label2, Kind: block.label1, Listen: fixtureOptionalString(filename, attrs["listen"]), Target: fixtureOptionalString(filename, attrs["target"]), TargetPort: uint16(targetPort), Tunnel: fixtureRefName(attrs["tunnel"])}, nil
}

func fixtureAttrs(body string) map[string]string {
	attrs := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "}" || strings.HasSuffix(line, "{") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		attrs[strings.TrimSpace(name)] = strings.TrimSpace(strings.TrimSuffix(value, ","))
	}
	return attrs
}

func nestedFixtureBlocks(body string) []fixtureBlock {
	var blocks []fixtureBlock
	for offset := 0; offset < len(body); {
		offset = skipFixtureSpace(body, offset)
		identifierStart := offset
		for offset < len(body) && (unicode.IsLetter(rune(body[offset])) || body[offset] == '_') {
			offset++
		}
		if identifierStart == offset {
			offset++
			continue
		}
		kind := body[identifierStart:offset]
		afterIdent := skipFixtureSpace(body, offset)
		if afterIdent >= len(body) || body[afterIdent] != '{' {
			lineEnd := strings.IndexByte(body[offset:], '\n')
			if lineEnd < 0 {
				break
			}
			offset += lineEnd + 1
			continue
		}
		end, err := findFixtureBlockEnd(body, afterIdent)
		if err != nil {
			break
		}
		blocks = append(blocks, fixtureBlock{kind: kind, body: body[afterIdent+1 : end]})
		offset = end + 1
	}
	return blocks
}

func removeNestedFixtureBlocks(body string) string {
	var builder strings.Builder
	for offset := 0; offset < len(body); {
		trimmedOffset := skipFixtureSpace(body, offset)
		for trimmedOffset < len(body) && (unicode.IsLetter(rune(body[trimmedOffset])) || body[trimmedOffset] == '_') {
			trimmedOffset++
		}
		afterIdent := skipFixtureSpace(body, trimmedOffset)
		if afterIdent < len(body) && body[afterIdent] == '{' {
			end, err := findFixtureBlockEnd(body, afterIdent)
			if err == nil {
				offset = end + 1
				continue
			}
		}
		lineEnd := strings.IndexByte(body[offset:], '\n')
		if lineEnd < 0 {
			builder.WriteString(body[offset:])
			break
		}
		builder.WriteString(body[offset : offset+lineEnd+1])
		offset += lineEnd + 1
	}
	return builder.String()
}

func unknownFixtureAttrs(attrs map[string]string, allowed ...string) []string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	var unknown []string
	for key := range attrs {
		if _, ok := allowedSet[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	return unknown
}

func fixtureStringList(value string) []string {
	var values []string
	for _, item := range fixtureList(value) {
		if strings.HasPrefix(strings.TrimSpace(item), "\"") {
			values = append(values, mustFixtureString("policy.hcl", item))
			continue
		}
		values = append(values, strings.TrimSpace(item))
	}
	return values
}

func fixtureList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	var values []string
	var builder strings.Builder
	inString := false
	escaped := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if inString {
			builder.WriteByte(char)
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == '"' {
				inString = false
			}
			continue
		}
		if char == '"' {
			inString = true
			builder.WriteByte(char)
			continue
		}
		if char == ',' {
			if item := strings.TrimSpace(builder.String()); item != "" {
				values = append(values, item)
			}
			builder.Reset()
			continue
		}
		builder.WriteByte(char)
	}
	if item := strings.TrimSpace(builder.String()); item != "" {
		values = append(values, item)
	}
	return values
}

func fixturePorts(filename string, value string) ([]PortRange, error) {
	var ports []PortRange
	for _, item := range fixtureList(value) {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(item, "\"") {
			rangeText := mustFixtureString(filename, item)
			parts := strings.Split(rangeText, "-")
			if len(parts) != 2 {
				return nil, fixtureLoadError(filename, "Invalid port range", fmt.Sprintf("invalid port range %q", rangeText))
			}
			start, err := fixturePortPart(filename, parts[0])
			if err != nil {
				return nil, err
			}
			end, err := fixturePortPart(filename, parts[1])
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fixtureLoadError(filename, "Invalid port range", fmt.Sprintf("port range %q ends before it starts", rangeText))
			}
			ports = append(ports, PortRange{Start: start, End: end})
			continue
		}
		if strings.Contains(item, ".") {
			return nil, fixtureLoadError(filename, "Invalid port", fmt.Sprintf("port %s must be an integer", item))
		}
		port, err := fixturePortPart(filename, item)
		if err != nil {
			return nil, fixtureLoadError(filename, "Invalid port", fmt.Sprintf("port %s is out of range", item))
		}
		ports = append(ports, PortRange{Start: port, End: port})
	}
	return ports, nil
}

func fixturePortPart(filename string, value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		return 0, fixtureLoadError(filename, "Invalid port", fmt.Sprintf("port %q is out of range", value))
	}
	return uint16(port), nil
}

func fixtureRefName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if before, after, ok := strings.Cut(value, "."); ok && before != "" {
		return strings.TrimSpace(after)
	}
	return value
}

func fixtureOptionalString(filename string, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return mustFixtureString(filename, value)
}

func mustFixtureString(filename string, value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "\"") {
		return value
	}
	unquoted, err := strconv.Unquote(value)
	if err != nil {
		panic(fmt.Sprintf("%s: invalid test fixture string %q: %v", filename, value, err))
	}
	return unquoted
}

func fixtureSize(value string) int64 {
	if value == "" {
		return 0
	}
	text := mustFixtureString("policy.hcl", value)
	multiplier := int64(1)
	if strings.HasSuffix(text, "KiB") {
		multiplier = 1024
		text = strings.TrimSuffix(text, "KiB")
	}
	size, _ := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	return size * multiplier
}

func fixtureLoadError(filename string, summary string, detail string) error {
	return &LoadError{Filename: filename, Diagnostics: []Diagnostic{{Severity: "error", Summary: summary, Detail: detail, File: filename, Line: 1, Column: 1}}}
}

func unsupportedFixtureArgumentDetail(names []string) string {
	var builder strings.Builder
	for index, name := range names {
		if index > 0 {
			builder.WriteByte('\n')
		}
		fmt.Fprintf(&builder, "An argument named %q is not expected here.", name)
	}
	return builder.String()
}
