package policy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestLoadedPolicyOmitsPolicyHash(t *testing.T) {
	compiled, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "metadata": {"policy_hash": "frontend-owned"},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}`))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.PolicyHash() != "" {
		t.Fatalf("canonical policy must not expose policy hash, got %q", compiled.PolicyHash())
	}
	if got := compiled.Metadata()["policy_hash"]; got != "frontend-owned" {
		t.Fatalf("expected frontend metadata to remain available, got %#v", got)
	}
}

func TestLoadCanonicalPolicy(t *testing.T) {
	compiled, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "metadata": {},
  "settings": {"default_action": "deny", "audit": {}},
  "endpoints": [{
    "kind": "https",
    "name": "api",
    "family": "http",
    "transport": "https-mitm",
    "tls": "terminate",
    "capabilities": ["credential-injection"],
    "hosts": ["api.example.com"]
  }],
  "credentials": [],
  "rules": [{"name": "allow-api", "endpoints": ["api"], "verdict": "allow"}],
  "tailscale": [],
  "forwards": []
}`))
	if err != nil {
		t.Fatalf("LoadReader returned error: %v", err)
	}
	if !compiled.HasHTTPS() {
		t.Fatal("HTTPS endpoint was not compiled")
	}
}

func TestLoadCanonicalPolicyRejectsUnsupportedVersion(t *testing.T) {
	_, err := LoadReader("policy.json", strings.NewReader(`{"version":2}`))
	if err == nil || !strings.Contains(err.Error(), "policy version must be 1") {
		t.Fatalf("unsupported version error = %v", err)
	}
}

func TestLoadCanonicalPolicyRejectsDescriptorlessEndpoint(t *testing.T) {
	_, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "endpoints": [{"kind":"https","name":"api","hosts":["api.example.com"]}]
}`))
	if err == nil || !strings.Contains(err.Error(), `requires family "http"`) {
		t.Fatalf("descriptorless endpoint error = %v", err)
	}
}

func TestLoadCanonicalPolicyRejectsMetadataMismatch(t *testing.T) {
	_, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "settings": {"default_action": "deny", "audit": {}},
  "endpoints": [{
    "kind": "https",
    "name": "api",
    "family": "package",
    "transport": "https-mitm",
    "tls": "terminate",
    "capabilities": ["credential-injection"],
    "hosts": ["api.example.com"]
  }]
}`))
	if err == nil || !strings.Contains(err.Error(), `requires family "http"`) {
		t.Fatalf("metadata mismatch error = %v", err)
	}
}

func TestLoadCanonicalRegistryEndpoint(t *testing.T) {
	compiled, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "settings": {"default_action": "deny", "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {
      "registries": ["npm", "pypi"],
      "malware_feed": "https://intelligence.example.com:8443/v1",
      "filter_package_age": 24
    },
    "egress": [{"host": "intelligence.example.com", "port": 8443, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com", "pypi.org", "files.pythonhosted.org", "pypi.python.org", "pythonhosted.org"]
  }],
  "rules": [{"name": "allow-old", "endpoints": ["public"], "condition": "package.age_known && package.age_hours >= 24", "verdict": "allow"}]
}`))
	if err != nil {
		t.Fatalf("LoadReader returned error: %v", err)
	}
	endpoint := compiled.registryEndpoints["registries.public"]
	if endpoint == nil || !slices.Equal(endpoint.Registries, []string{"npm", "pypi"}) || endpoint.Egress.Port != 8443 || endpoint.FilterPackageAge != 24 {
		t.Fatalf("unexpected registry endpoint: %#v", endpoint)
	}
	decision := compiled.EvaluateAction(Ref{Kind: "registries", Name: "public"}, FacetValues{
		"http": {
			"method":  "GET",
			"host":    "registry.npmjs.org",
			"path":    "/package",
			"query":   map[string][]string{},
			"headers": map[string][]string{},
		},
		"package": {
			"ecosystem":              "npm",
			"operation":              "download",
			"name":                   "package",
			"version":                "1.0.0",
			"identity_known":         true,
			"age_known":              true,
			"age_hours":              24,
			"age_source":             "registry_metadata",
			"malware_data_available": true,
			"malware":                false,
		},
	})
	if decision.Action != ActionAllow || decision.RuleName != "allow-old" {
		t.Fatalf("registry action decision = %#v", decision)
	}
}

func TestLoadCanonicalPolicyRejectsPluginFields(t *testing.T) {
	for _, field := range []string{
		`"plugins": []`,
		`"endpoints": [{"kind":"https","name":"api","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"plugin":"echo","hosts":["api.example.com"]}]`,
	} {
		_, err := LoadReader("policy.json", strings.NewReader(`{"version":1,`+field+`}`))
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("plugin field %s error = %v", field, err)
		}
	}
}

func TestLoadCanonicalRegistryEndpointRejectsDerivedEnvelopeMismatch(t *testing.T) {
	tests := []struct {
		name   string
		config string
		egress string
		hosts  string
		want   string
	}{
		{name: "unknown registry", config: `{"registries":["rubygems"],"malware_feed":"https://intelligence.example.com"}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["rubygems.org"]`, want: "registry names must be npm or pypi"},
		{name: "duplicate registry", config: `{"registries":["npm","npm"],"malware_feed":"https://intelligence.example.com"}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["registry.npmjs.org","registry.yarnpkg.com","registry.npmjs.com"]`, want: "declared more than once"},
		{name: "host mismatch", config: `{"registries":["npm"],"malware_feed":"https://intelligence.example.com"}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["attacker.example.com"]`, want: "host bindings do not match"},
		{name: "egress mismatch", config: `{"registries":["npm"],"malware_feed":"https://intelligence.example.com"}`, egress: `[{"host":"attacker.example.com","port":443,"tls":true}]`, hosts: `["registry.npmjs.org","registry.yarnpkg.com","registry.npmjs.com"]`, want: "egress does not match"},
		{name: "non HTTPS intelligence", config: `{"registries":["npm"],"malware_feed":"http://intelligence.example.com"}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["registry.npmjs.org","registry.yarnpkg.com","registry.npmjs.com"]`, want: "must be an HTTPS URL"},
		{name: "zero package age", config: `{"registries":["npm"],"malware_feed":"https://intelligence.example.com","filter_package_age":0}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["registry.npmjs.org","registry.yarnpkg.com","registry.npmjs.com"]`, want: "filter_package_age must be a positive integer"},
		{name: "fractional package age", config: `{"registries":["npm"],"malware_feed":"https://intelligence.example.com","filter_package_age":1.5}`, egress: `[{"host":"intelligence.example.com","port":443,"tls":true}]`, hosts: `["registry.npmjs.org","registry.yarnpkg.com","registry.npmjs.com"]`, want: "filter_package_age must be a positive integer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"version":1,"endpoints":[{"kind":"registries","name":"public","family":"package","transport":"tls-terminate","tls":"terminate","config":%s,"egress":%s,"hosts":%s}]}`, test.config, test.egress, test.hosts)
			_, err := LoadReader("policy.json", strings.NewReader(body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDefaultPolicyHasNoPolicyHash(t *testing.T) {
	compiled := Default()
	if compiled.PolicyHash() != "" {
		t.Fatalf("expected implicit default policy to have no hash, got %q", compiled.PolicyHash())
	}

	decision := compiled.EvaluateFlow(Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("192.0.2.10"), DestPort: 443})
	if decision.Action != ActionAllow || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected default policy to allow, got %#v", decision)
	}
}

func TestAuditSettingsRejectSinkControls(t *testing.T) {
	_, err := loadPolicyError(t, `
settings {
  audit {
    path = "audit.jsonl"
    enabled = true
  }
}
`)
	if err == nil {
		t.Fatal("expected audit sink controls to be rejected")
	}
	text := err.Error()
	if !strings.Contains(text, `An argument named "path" is not expected here.`) || !strings.Contains(text, `An argument named "enabled" is not expected here.`) {
		t.Fatalf("expected audit sink controls to be rejected, got %v", err)
	}
}

func TestDefaultActionDefaultsToAllow(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443]
}
`)

	decision := compiled.EvaluateFlow(Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("192.0.2.10"),
		DestPort: 443,
	})
	if decision.Action != ActionAllow || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected default allow, got %#v", decision)
	}
}

func TestFlowRulesUsePriorityThenDeclarationOrder(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443]
}

rule "lower-deny" {
  endpoint = ip.private
  verdict = "deny"
  priority = 10
}

rule "first-allow" {
  endpoint = ip.private
  verdict = "allow"
  priority = 20
}

rule "second-deny" {
  endpoint = ip.private
  verdict = "deny"
  priority = 20
}
`)

	decision := compiled.EvaluateFlow(Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("10.1.2.3"),
		DestPort: 443,
	})
	if decision.Action != ActionAllow || decision.RuleName != "first-allow" {
		t.Fatalf("expected first high-priority allow, got %#v", decision)
	}
}

func TestDisabledRulesAreValidatedButNotEvaluated(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443]
}

rule "disabled-deny" {
  endpoint = ip.private
  verdict = "deny"
  disabled = true
  priority = 100
}

rule "allow" {
  endpoint = ip.private
  verdict = "allow"
  priority = 1
}
`)

	decision := compiled.EvaluateFlow(Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("10.1.2.3"),
		DestPort: 443,
	})
	if decision.Action != ActionAllow || decision.RuleName != "allow" {
		t.Fatalf("expected disabled rule to be skipped, got %#v", decision)
	}

	_, err := loadPolicyError(t, `
endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
}

rule "disabled-invalid" {
  endpoint = ip.private
  verdict = "deny"
  condition = "http.method == 'GET'"
  disabled = true
}
`)
	if err == nil || !strings.Contains(err.Error(), "condition") {
		t.Fatalf("expected disabled invalid rule to fail validation, got %v", err)
	}
}

func TestHTTPFamilyRulesMayMixHTTPAndHTTPS(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

rule "http-family-read" {
  endpoints = [http.metadata, https.github]
  condition = "http.method in ['GET', 'HEAD']"
  verdict = "allow"
}
`)

	cleartext := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "http", Host: "metadata.internal", Method: http.MethodGet, Path: "/latest"})
	if cleartext.Action != ActionAllow || cleartext.EndpointKind != "http" {
		t.Fatalf("expected http allow, got %#v", cleartext)
	}
	https := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.github.com:443", Method: http.MethodGet, Path: "/repos"})
	if https.Action != ActionAllow || https.EndpointKind != "https" {
		t.Fatalf("expected https allow, got %#v", https)
	}
}

func TestHTTPHostBindingsMatchADRNormalization(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "http" "exact" {
  hosts = ["Example.COM", "api.example.com:8080", "192.0.2.10", "[2001:db8::1]"]
}

endpoint "http" "wildcard" {
  hosts = ["*.example.com", "*.wild.test"]
}

endpoint "http" "nested" {
  hosts = ["*.svc.example.com"]
}
`)

	tests := []struct {
		host     string
		endpoint string
	}{
		{host: "EXAMPLE.com", endpoint: "exact"},
		{host: "example.com:80", endpoint: "exact"},
		{host: "api.example.com:8080", endpoint: "exact"},
		{host: "api.example.com", endpoint: "wildcard"},
		{host: "192.0.2.10", endpoint: "exact"},
		{host: "192.0.2.10:80", endpoint: "exact"},
		{host: "[2001:DB8::1]", endpoint: "exact"},
		{host: "[2001:db8::1]:80", endpoint: "exact"},
		{host: "one.wild.test", endpoint: "wildcard"},
		{host: "svc.example.com", endpoint: "wildcard"},
		{host: "service.svc.example.com", endpoint: "nested"},
		{host: "deep.service.svc.example.com", endpoint: "nested"},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			ref, endpoint, ok := compiled.MatchHTTPFamilyHost("http", test.host)
			if !ok || ref.Kind != "http" || ref.Name != test.endpoint || endpoint.Name != test.endpoint {
				t.Fatalf("MatchHTTPFamilyHost(%q) = (%#v, %#v, %v), want http.%s", test.host, ref, endpoint, ok, test.endpoint)
			}
		})
	}

	for _, host := range []string{"wild.test", "api.example.com:9090", "2001:db8::1"} {
		t.Run("miss "+host, func(t *testing.T) {
			if ref, _, ok := compiled.MatchHTTPFamilyHost("http", host); ok {
				t.Fatalf("expected %q not to match, got %#v", host, ref)
			}
		})
	}
}

func TestHTTPSHostBindingsMatchWildcards(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "https" "generic" {
  hosts = ["*.example.com"]
}

endpoint "https" "service" {
  hosts = ["*.svc.example.com"]
}
`)

	tests := []struct {
		host      string
		endpoint  string
		authority string
		certHost  string
	}{
		{host: "api.example.com", endpoint: "generic", authority: "api.example.com", certHost: "api.example.com"},
		{host: "deep.api.example.com", endpoint: "generic", authority: "deep.api.example.com", certHost: "deep.api.example.com"},
		{host: "API.SVC.EXAMPLE.COM", endpoint: "service", authority: "api.svc.example.com", certHost: "api.svc.example.com"},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			ref, authority, certHost, ok := compiled.ResolveHTTPSHost(test.host, 443)
			if !ok || ref.Kind != "https" || ref.Name != test.endpoint || authority != test.authority || certHost != test.certHost {
				t.Fatalf("ResolveHTTPSHost(%q) = (%#v, %q, %q, %v), want https.%s %q %q true", test.host, ref, authority, certHost, ok, test.endpoint, test.authority, test.certHost)
			}
		})
	}

	if ref, _, _, ok := compiled.ResolveHTTPSHost("example.com", 443); ok {
		t.Fatalf("wildcard must not match apex host, got %#v", ref)
	}
	if ref, _, _, ok := compiled.ResolveHTTPSHost("api.example.com", 8443); ok {
		t.Fatalf("wildcard must not match wrong port, got %#v", ref)
	}
}

func TestHTTPClassificationUsesConfiguredEndpointPorts(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal:8080"]
}
`)

	if !compiled.ShouldInterceptHTTP(8080) {
		t.Fatal("expected explicitly configured http port 8080 to be intercepted")
	}
	if compiled.ShouldInterceptHTTP(80) {
		t.Fatal("did not expect port 80 interception without a port 80 http binding")
	}

	decision := compiled.EvaluateFlow(Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("169.254.169.254"), DestPort: 8080})
	if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault || !decision.ClassificationOpportunity {
		t.Fatalf("expected default-deny classification on configured http port, got %#v", decision)
	}

	decision = compiled.EvaluateFlow(Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("169.254.169.254"), DestPort: 80})
	if decision.Action != ActionDeny || decision.ClassificationOpportunity {
		t.Fatalf("expected unconfigured http port to remain flow default deny, got %#v", decision)
	}
}

func TestDuplicateHTTPExactHostBindingsAreRejected(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "http" "one" {
  hosts = ["Example.COM"]
}

endpoint "http" "two" {
  hosts = ["example.com:80"]
}
`)
	if err == nil || !strings.Contains(err.Error(), "duplicates exact binding") {
		t.Fatalf("expected duplicate exact http binding error, got %v", err)
	}

	loadPolicy(t, `
endpoint "http" "cleartext" {
  hosts = ["api.example.com"]
}

endpoint "https" "tls" {
  hosts = ["api.example.com"]
}
`)
}

func TestHTTPEndpointHostsAreRequiredAndValidated(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "http" "missing" {
}
`)
	if err == nil || !strings.Contains(err.Error(), "Missing hosts") {
		t.Fatalf("expected missing hosts error, got %v", err)
	}

	tests := []string{
		"",
		"http://example.com",
		"example.com/path",
		"example.com?debug=1",
		"example.com#fragment",
		"user:pass@example.com",
		"example.com:http",
		"example.com:0",
		"example.com:65536",
		"bad host.example",
		"café.example",
		"2001:db8::1",
		"[192.0.2.10]",
		"*.0.0.1",
		"*.168.1.1",
	}
	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			_, err := loadPolicyError(t, fmt.Sprintf(`
endpoint "http" "bad" {
  hosts = [%q]
}
`, host))
			if err == nil {
				t.Fatalf("expected host binding %q to be rejected", host)
			}
		})
	}
}

func TestCredentialsCannotBindToHTTPEndpoints(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

credential "bearer_token" "metadata" {
  endpoint = http.metadata
}
`)
	if err == nil || !strings.Contains(err.Error(), "must reference an https endpoint") {
		t.Fatalf("expected http credential binding to be rejected, got %v", err)
	}
}

func TestUnknownHTTPHostsUseDefaultActionWithoutCredentials(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "http", Host: "unknown.internal", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionAllow || decision.Source != DecisionSourceDefault || decision.Reason != "unknown_l7_endpoint" {
		t.Fatalf("expected unknown http host to use default allow, got %#v", decision)
	}
	if decision.SelectedCredential != nil {
		t.Fatalf("unknown http host must not borrow credentials, got %#v", decision.SelectedCredential)
	}

	compiled = loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	decision = compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "http", Host: "unknown.internal", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault || decision.Reason != "default_deny" {
		t.Fatalf("expected unknown http host to use default deny, got %#v", decision)
	}
}

func TestHTTPCELRequestFacets(t *testing.T) {
	request := HTTPRequest{
		EndpointKind: "https",
		Host:         "api.example.com:443",
		Method:       "gEt",
		Path:         "/decoded/path",
		Query:        "tag=one&tag=two&space=a+b&encoded=x%2Fy",
		Header: http.Header{
			"Authorization": {"Bearer token"},
			"X-Token":       {"secret"},
			"x-token":       {"second"},
		},
	}

	tests := []struct {
		name      string
		condition string
	}{
		{name: "method equality", condition: "http.method == 'GET'"},
		{name: "method reversed equality", condition: "'GET' == http.method"},
		{name: "method membership", condition: "http.method in ['POST', 'GET']"},
		{name: "method prefix", condition: "http.method.startsWith('GE')"},
		{name: "host", condition: "http.host == 'api.example.com'"},
		{name: "path", condition: "http.path == '/decoded/path'"},
		{name: "query repeated", condition: "http.query['tag'] == ['one', 'two']"},
		{name: "query percent decoded", condition: "http.query['space'][0] == 'a b' && http.query['encoded'][0] == 'x/y'"},
		{name: "query missing", condition: "size(http.query['missing']) == 0"},
		{name: "query field select", condition: "http.query.tag[1] == 'two'"},
		{name: "headers case insensitive", condition: "http.headers['x-token'][0] == 'secret' && http.headers['X-TOKEN'][1] == 'second'"},
		{name: "headers missing", condition: "size(http.headers['missing']) == 0"},
		{name: "headers field select", condition: "http.headers.authorization[0] == 'Bearer token'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled := loadPolicy(t, httpConditionPolicy(tt.condition))
			decision := compiled.EvaluateHTTP(request)
			if decision.Action != ActionAllow || decision.RuleName != "allow" {
				_, matchErr := compiled.rulesByFamily[EndpointFamilyHTTP][0].matchesHTTP(request)
				t.Fatalf("expected condition %q to allow, got %#v (condition error: %v)", tt.condition, decision, matchErr)
			}
		})
	}
}

func TestHTTPCELRequestFacetLoadErrors(t *testing.T) {
	tests := []struct {
		name      string
		condition string
	}{
		{name: "parse error", condition: "http.method =="},
		{name: "body unavailable", condition: "http.body == ''"},
		{name: "body json unavailable", condition: "http.body_json.enabled == true"},
		{name: "scalar header alias unavailable", condition: "http.header.authorization == 'Bearer token'"},
		{name: "raw path unavailable", condition: "http.raw_path == '/raw'"},
		{name: "escaped path unavailable", condition: "http.escaped_path == '/escaped'"},
		{name: "unknown variable", condition: "http.unknown == 'value'"},
		{name: "non bool result", condition: "http.method"},
		{name: "query type mismatch", condition: "http.query == 'tag=one'"},
		{name: "header list scalar mismatch", condition: "http.headers['authorization'] == 'Bearer token'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadPolicyError(t, httpConditionPolicy(tt.condition))
			if err == nil {
				t.Fatalf("expected condition %q to fail policy load", tt.condition)
			}
		})
	}
}

func TestReferencesAllowHCLIdentifiersWithDashes(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "openai-codex" {
  hosts = ["chatgpt.com"]
}

credential "bearer_token" "api-token" {
  endpoint = https.openai-codex
}

rule "allow-codex" {
  endpoint = https.openai-codex
  credential = bearer_token.api-token
  verdict = "allow"
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "chatgpt.com", Method: http.MethodGet})
	if decision.Action != ActionAllow || decision.RuleName != "allow-codex" {
		t.Fatalf("expected dashed endpoint reference to allow, got %#v", decision)
	}
	if decision.EndpointName != "openai-codex" {
		t.Fatalf("expected dashed endpoint name, got %q", decision.EndpointName)
	}
	if decision.SelectedCredential == nil || decision.SelectedCredential.Name != "api-token" {
		t.Fatalf("expected dashed credential name, got %#v", decision.SelectedCredential)
	}
}

func TestCredentialProviderMetadataReachesRuntime(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "git" {
  hosts = ["git.example.com"]
}

endpoint "https" "internal" {
  hosts = ["internal.example.com"]
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "basic_auth" "git-basic" {
  endpoint = https.git
  username = "octo"
}

credential "header_token" "internal-api" {
  endpoint = https.internal
  header = "X-Internal-Token"
  prefix = "Token "
}

credential "bearer_token" "api-token" {
  endpoint = https.api
  idempotency_key = true
}

rule "allow-git" {
  endpoint = https.git
  verdict = "allow"
}

rule "allow-internal" {
  endpoint = https.internal
  verdict = "allow"
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	basic := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "git.example.com", Method: http.MethodGet})
	if basic.SelectedCredential == nil || basic.SelectedCredential.Kind != "basic_auth" || basic.SelectedCredential.Username != "octo" {
		t.Fatalf("expected basic_auth metadata, got %#v", basic.SelectedCredential)
	}

	header := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "internal.example.com", Method: http.MethodGet})
	if header.SelectedCredential == nil || header.SelectedCredential.Kind != "header_token" || header.SelectedCredential.Header != "X-Internal-Token" || header.SelectedCredential.Prefix != "Token " {
		t.Fatalf("expected header_token metadata, got %#v", header.SelectedCredential)
	}

	bearer := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet})
	if bearer.SelectedCredential == nil || bearer.SelectedCredential.Kind != "bearer_token" || !bearer.SelectedCredential.IdempotencyKey {
		t.Fatalf("expected bearer_token metadata, got %#v", bearer.SelectedCredential)
	}
}

func TestMixedEndpointFamiliesAreRejected(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

rule "mixed" {
  endpoints = [ip.private, https.github]
  verdict = "allow"
}
`)
	if err == nil || !strings.Contains(err.Error(), "same family") {
		t.Fatalf("expected mixed family error, got %v", err)
	}
}

func TestUnknownFieldsAndUnsupportedSyntaxAreRejected(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "invalid_endpoint" "private" {
  destination = ["10.0.0.0/8"]
}
`)
	if err == nil || !strings.Contains(err.Error(), `unsupported endpoint kind "invalid_endpoint"`) {
		t.Fatalf("expected unsupported endpoint kind error, got %v", err)
	}

	_, err = loadPolicyError(t, `
settings {
  surprise = "/tmp/nope"
}
`)
	if err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("expected unknown settings field error, got %v", err)
	}

	_, err = loadPolicyError(t, `
endpoint "ip" "private" {
  surprise = ["10.0.0.0/8"]
}
`)
	if err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("expected unknown endpoint field error, got %v", err)
	}
}

func TestPortNumbersMustBeIntegers(t *testing.T) {
	_, err := loadPolicyError(t, `
endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443.5]
}
`)
	if err == nil || !strings.Contains(err.Error(), "port 443.5 must be an integer") {
		t.Fatalf("expected fractional port error, got %v", err)
	}
}

func TestIPEndpointExactTCPPortMatches(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443]
}

rule "allow-private" {
  endpoint = ip.private
  verdict = "allow"
}
`)

	decision := compiled.EvaluateFlow(l4Flow("tcp", 443))
	if decision.Action != ActionAllow || decision.RuleName != "allow-private" {
		t.Fatalf("expected tcp 443 allow, got %#v", decision)
	}
	assertL4Match(t, decision, L4Match{EndpointProtocol: "tcp", DestPort: 443, PortRange: PortRange{Start: 443, End: 443}, Kind: L4MatchExactPort})

	decision = compiled.EvaluateFlow(l4Flow("tcp", 444))
	if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected tcp 444 default deny, got %#v", decision)
	}
	if decision.MatchedL4 != nil {
		t.Fatalf("default decision must not carry l4 metadata, got %#v", decision.MatchedL4)
	}
}

func TestIPEndpointExactUDPPortMatches(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "dns" {
  destination = ["10.0.0.0/8"]
  protocol = "udp"
  ports = [53]
}

rule "allow-dns" {
  endpoint = ip.dns
  verdict = "allow"
}
`)

	decision := compiled.EvaluateFlow(l4Flow("udp", 53))
	if decision.Action != ActionAllow || decision.RuleName != "allow-dns" {
		t.Fatalf("expected udp 53 allow, got %#v", decision)
	}
	assertL4Match(t, decision, L4Match{EndpointProtocol: "udp", DestPort: 53, PortRange: PortRange{Start: 53, End: 53}, Kind: L4MatchExactPort})

	decision = compiled.EvaluateFlow(l4Flow("tcp", 53))
	if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected tcp 53 to miss udp endpoint, got %#v", decision)
	}
}

func TestIPEndpointPortRangesAreInclusive(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "app" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["8000-8002"]
}

rule "allow-app" {
  endpoint = ip.app
  verdict = "allow"
}
`)

	for _, port := range []uint16{8000, 8001, 8002} {
		decision := compiled.EvaluateFlow(l4Flow("tcp", port))
		if decision.Action != ActionAllow || decision.RuleName != "allow-app" {
			t.Fatalf("expected tcp %d allow, got %#v", port, decision)
		}
		assertL4Match(t, decision, L4Match{EndpointProtocol: "tcp", DestPort: port, PortRange: PortRange{Start: 8000, End: 8002}, Kind: L4MatchRange})
	}

	for _, port := range []uint16{7999, 8003} {
		decision := compiled.EvaluateFlow(l4Flow("tcp", port))
		if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault {
			t.Fatalf("expected tcp %d default deny, got %#v", port, decision)
		}
	}
}

func TestIPEndpointBoundaryPortsMatch(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "boundaries" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [1, 65535]
}

rule "allow-boundaries" {
  endpoint = ip.boundaries
  verdict = "allow"
}
`)

	for _, port := range []uint16{1, 65535} {
		decision := compiled.EvaluateFlow(l4Flow("tcp", port))
		if decision.Action != ActionAllow || decision.RuleName != "allow-boundaries" {
			t.Fatalf("expected tcp %d allow, got %#v", port, decision)
		}
		assertL4Match(t, decision, L4Match{EndpointProtocol: "tcp", DestPort: port, PortRange: PortRange{Start: port, End: port}, Kind: L4MatchExactPort})
	}
}

func TestIPEndpointDefaultProtocolMatchesAnyWithoutPorts(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "private" {
  destination = ["10.0.0.0/8"]
}

rule "allow-private" {
  endpoint = ip.private
  verdict = "allow"
}
`)

	for _, protocol := range []string{"tcp", "udp"} {
		decision := compiled.EvaluateFlow(l4Flow(protocol, 8443))
		if decision.Action != ActionAllow || decision.RuleName != "allow-private" {
			t.Fatalf("expected %s flow allow, got %#v", protocol, decision)
		}
		assertL4Match(t, decision, L4Match{EndpointProtocol: "any", DestPort: 8443, Kind: L4MatchProtocolOnly})
	}
}

func TestIPEndpointPortRangesAreCanonicalized(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "ip" "canonical" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [443, "8000-8002", "8001-8003", 443, "444-445", "446-446"]
}
`)

	endpoint := compiled.ipEndpoints["ip.canonical"]
	if endpoint == nil {
		t.Fatal("expected ip.canonical endpoint")
	}
	want := []PortRange{{Start: 443, End: 446}, {Start: 8000, End: 8003}}
	if len(endpoint.Ports) != len(want) {
		t.Fatalf("expected canonical ports %#v, got %#v", want, endpoint.Ports)
	}
	for i := range want {
		if endpoint.Ports[i] != want[i] {
			t.Fatalf("expected canonical ports %#v, got %#v", want, endpoint.Ports)
		}
	}
}

func TestInvalidIPEndpointL4PolicyIsRejected(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "ports default to protocol any",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  ports = [443]
}
`,
			want: "protocol any cannot be combined with ports",
		},
		{
			name: "ports with protocol any",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "any"
  ports = [443]
}
`,
			want: "protocol any cannot be combined with ports",
		},
		{
			name: "port zero",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [0]
}
`,
			want: "port 0 is out of range",
		},
		{
			name: "port too high",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = [65536]
}
`,
			want: "port 65536 is out of range",
		},
		{
			name: "reversed range",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["9000-8000"]
}
`,
			want: `port range "9000-8000" ends before it starts`,
		},
		{
			name: "malformed range",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["8000-9000-10000"]
}
`,
			want: `invalid port range "8000-9000-10000"`,
		},
		{
			name: "quoted exact port",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["443"]
}
`,
			want: `invalid port range "443"`,
		},
		{
			name: "non integer range",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["53.5-54"]
}
`,
			want: `port "53.5" is out of range`,
		},
		{
			name: "unsupported protocol",
			body: `
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol = "icmp"
}
`,
			want: `unsupported protocol "icmp"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadPolicyError(t, test.body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestExplicitIPDenyIsTerminalBeforeL7Classification(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "blocked" {
  destination = ["203.0.113.0/24"]
  protocol = "tcp"
  ports = [443]
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

rule "block" {
  endpoint = ip.blocked
  verdict = "deny"
  priority = 100
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	decision := compiled.EvaluateFlow(Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("203.0.113.10"),
		DestPort: 443,
	})
	if decision.Action != ActionDeny || decision.Source != DecisionSourceRule || decision.ClassificationOpportunity {
		t.Fatalf("expected terminal ip deny, got %#v", decision)
	}
}

func TestDefaultDenyAllowsL7ClassificationOnly(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

rule "allow-metadata" {
  endpoint = http.metadata
  verdict = "allow"
}
`)

	flowDecision := compiled.EvaluateFlow(Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("169.254.169.254"),
		DestPort: 80,
	})
	if flowDecision.Action != ActionDeny || flowDecision.Source != DecisionSourceDefault || !flowDecision.ClassificationOpportunity {
		t.Fatalf("expected default-deny classification opportunity, got %#v", flowDecision)
	}

	requestDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "http", Host: "metadata.internal", Method: http.MethodGet, Path: "/latest"})
	if requestDecision.Action != ActionAllow || requestDecision.Source != DecisionSourceRule {
		t.Fatalf("expected L7 rule allow after classification, got %#v", requestDecision)
	}
}

func TestHTTPSClassificationUsesConfiguredEndpointPorts(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com:8443"]
}
`)

	if !compiled.ShouldInterceptHTTPS(8443) {
		t.Fatal("expected explicitly configured https port 8443 to be intercepted")
	}
	if compiled.ShouldInterceptHTTPS(443) {
		t.Fatal("did not expect port 443 interception without a port 443 https binding")
	}

	decision := compiled.EvaluateFlow(Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("203.0.113.10"), DestPort: 8443})
	if decision.Action != ActionDeny || decision.Source != DecisionSourceDefault || !decision.ClassificationOpportunity {
		t.Fatalf("expected default-deny classification on configured port, got %#v", decision)
	}

	decision = compiled.EvaluateFlow(Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("203.0.113.10"), DestPort: 443})
	if decision.Action != ActionDeny || decision.ClassificationOpportunity {
		t.Fatalf("expected unconfigured port to remain flow default deny, got %#v", decision)
	}
}

func TestResolveHTTPSRawIPMatchesOnlyExactIPBindings(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "https" "proxmox" {
  hosts = ["203.0.113.10:8006"]
}

endpoint "https" "api" {
  hosts = ["api.example.com", "*.example.net"]
}
`)

	ref, authority, certHost, ok := compiled.ResolveHTTPSRawIP(net.ParseIP("203.0.113.10"), 8006)
	if !ok || ref.Name != "proxmox" || authority != "203.0.113.10:8006" || certHost != "203.0.113.10" {
		t.Fatalf("raw IP resolution = (%#v, %q, %q, %v), want proxmox 203.0.113.10:8006 203.0.113.10 true", ref, authority, certHost, ok)
	}
	if _, _, _, ok := compiled.ResolveHTTPSRawIP(net.ParseIP("203.0.113.10"), 8443); ok {
		t.Fatal("did not expect raw IP binding to match the wrong port")
	}
	if _, _, _, ok := compiled.ResolveHTTPSRawIP(net.ParseIP("203.0.113.11"), 8006); ok {
		t.Fatal("did not expect raw IP binding to match the wrong IP")
	}
}

func TestConditionRuntimeErrorsFailClosed(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

rule "bad-condition" {
  endpoint = https.api
  condition = "http.headers['x-missing'][0] == 'yes'"
  verdict = "allow"
  priority = 20
}

rule "lower-allow" {
  endpoint = https.api
  verdict = "allow"
  priority = 10
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionDeny || decision.Reason != "condition_error" || decision.RuleName != "bad-condition" {
		t.Fatalf("expected condition error deny, got %#v", decision)
	}
}

func TestCredentialConditionsSelectOneCredential(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "reader" {
  endpoint = https.api
  condition = "http.path.startsWith('/read')"
}

credential "bearer_token" "writer" {
  endpoint = https.api
  condition = "http.method == 'POST'"
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	readDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/read/status"})
	if readDecision.Action != ActionAllow || readDecision.SelectedCredential == nil || readDecision.SelectedCredential.Name != "reader" {
		t.Fatalf("expected reader credential selection, got %#v", readDecision)
	}

	writeDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodPost, Path: "/write"})
	if writeDecision.Action != ActionAllow || writeDecision.SelectedCredential == nil || writeDecision.SelectedCredential.Name != "writer" {
		t.Fatalf("expected writer credential selection, got %#v", writeDecision)
	}

	publicDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/public"})
	if publicDecision.Action != ActionAllow || publicDecision.SelectedCredential != nil {
		t.Fatalf("expected explicit allow without credential injection, got %#v", publicDecision)
	}
}

func TestCredentialConditionRuntimeErrorsFailClosed(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
  condition = "http.headers['x-missing'][0] == 'yes'"
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionDeny || decision.Reason != "credential_condition_error" || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected credential condition error deny, got %#v", decision)
	}
}

func TestAmbiguousCredentialsFailClosedBeforeRules(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "one" {
  endpoint = https.api
}

credential "bearer_token" "two" {
  endpoint = https.api
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionDeny || decision.Reason != "ambiguous_credentials" || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected ambiguous credential deny, got %#v", decision)
	}
}

func TestRuleCredentialIsPredicateNotInjectionTrigger(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
  condition = "http.path.startsWith('/private')"
}

rule "credentialed" {
  endpoint = https.api
  credential = bearer_token.api
  verdict = "allow"
  priority = 20
}

rule "public" {
  endpoint = https.api
  verdict = "allow"
  priority = 10
}
`)

	privateDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/private"})
	if privateDecision.Action != ActionAllow || privateDecision.RuleName != "credentialed" || privateDecision.SelectedCredential == nil || privateDecision.SelectedCredential.Name != "api" {
		t.Fatalf("expected credential predicate rule to match selected credential, got %#v", privateDecision)
	}

	publicDecision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/public"})
	if publicDecision.Action != ActionAllow || publicDecision.RuleName != "public" || publicDecision.SelectedCredential != nil {
		t.Fatalf("expected credential predicate to skip without selecting credentials, got %#v", publicDecision)
	}
}

func TestUDP443IsNotHTTP3Inspected(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}
`)

	decision := compiled.EvaluateFlow(Flow{Protocol: "udp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("203.0.113.10"), DestPort: 443})
	if decision.Action != ActionDeny || decision.ClassificationOpportunity {
		t.Fatalf("expected UDP/443 to remain non-classified default deny, got %#v", decision)
	}

	compiled = loadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

endpoint "ip" "quic" {
  destination = ["203.0.113.0/24"]
  protocol = "udp"
  ports = [443]
}

rule "allow-quic" {
  endpoint = ip.quic
  verdict = "allow"
}
`)

	decision = compiled.EvaluateFlow(Flow{Protocol: "udp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("203.0.113.10"), DestPort: 443})
	if decision.Action != ActionAllow || decision.RuleName != "allow-quic" || decision.ClassificationOpportunity {
		t.Fatalf("expected UDP/443 to follow normal ip endpoint handling without classification, got %#v", decision)
	}
}

func TestCredentialMetadataDoesNotApplyOnDefaultAllow(t *testing.T) {
	compiled := loadPolicy(t, `
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
}
`)

	decision := compiled.EvaluateHTTP(HTTPRequest{EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet, Path: "/"})
	if decision.Action != ActionAllow || decision.Source != DecisionSourceDefault {
		t.Fatalf("expected default allow, got %#v", decision)
	}
	if decision.SelectedCredential != nil {
		t.Fatalf("default allow must not select credentials, got %#v", decision.SelectedCredential)
	}
}

func TestAuditSettingsWarningsArePolicyDiagnostics(t *testing.T) {
	compiled := loadPolicy(t, `
settings {
  audit {
    body_buffer = "1KiB"
    body_storage = "4KiB"
  }
}
`)
	diagnostics := compiled.Diagnostics()
	if len(diagnostics) != 1 || diagnostics[0].Severity != "warning" || !strings.Contains(diagnostics[0].Detail, "body_buffer") {
		t.Fatalf("expected audit warning diagnostic, got %#v", diagnostics)
	}
}

func TestLoadFileRejectsUnknownCanonicalFields(t *testing.T) {
	_, err := LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "policy_hash": "sha256:old-contract",
  "metadata": {},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}`))
	if err == nil {
		t.Fatal("expected invalid policy to fail")
	}
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("expected LoadError, got %T", err)
	}
	if len(loadErr.Diagnostics) != 1 || !strings.Contains(loadErr.Diagnostics[0].Detail, "policy_hash") {
		t.Fatalf("expected unknown policy_hash diagnostic, got %#v", loadErr.Diagnostics)
	}
}

func TestLoadFileRejectsNonObjectMetadata(t *testing.T) {
	for _, metadata := range []string{"null", "[]", `"hash"`} {
		_, err := LoadReader("policy.json", strings.NewReader(fmt.Sprintf(`{
  "version": 1,
  "metadata": %s,
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}`, metadata)))
		if err == nil {
			t.Fatalf("expected metadata %s to fail", metadata)
		}
		var loadErr *LoadError
		if !errors.As(err, &loadErr) {
			t.Fatalf("expected LoadError, got %T", err)
		}
		if len(loadErr.Diagnostics) != 1 || loadErr.Diagnostics[0].Summary != "Invalid metadata" {
			t.Fatalf("expected invalid metadata diagnostic, got %#v", loadErr.Diagnostics)
		}
	}
}

func loadPolicy(t *testing.T, text string) *Policy {
	t.Helper()
	compiled, err := loadPolicyError(t, text)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	return compiled
}

func loadPolicyError(t *testing.T, text string) (*Policy, error) {
	t.Helper()
	return loadHCLFixtureForTest("policy.hcl", []byte(text))
}

func httpConditionPolicy(condition string) string {
	return fmt.Sprintf(`
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

rule "allow" {
  endpoint = https.api
  condition = %q
  verdict = "allow"
}
`, condition)
}

func l4Flow(protocol string, destPort uint16) Flow {
	return Flow{
		Protocol: protocol,
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("10.1.2.3"),
		DestPort: destPort,
	}
}

func assertL4Match(t *testing.T, decision Decision, want L4Match) {
	t.Helper()
	if decision.MatchedL4 == nil {
		t.Fatalf("expected l4 match %#v, got nil", want)
	}
	if *decision.MatchedL4 != want {
		t.Fatalf("expected l4 match %#v, got %#v", want, *decision.MatchedL4)
	}
}
