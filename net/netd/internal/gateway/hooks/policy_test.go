package hooks

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/policy/policytest"
)

func TestPolicyHookCarriesL4MatchMetadata(t *testing.T) {
	compiled := policytest.LoadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "app" {
  destination = ["10.0.0.0/8"]
  protocol = "tcp"
  ports = ["8443-9443"]
}

rule "allow-app" {
  endpoint = ip.app
  verdict = "allow"
}
`)

	decision, err := NewPolicyHook(compiled).Decide(context.Background(), Flow{
		Protocol: "tcp",
		SourceIP: net.ParseIP("192.168.127.2"),
		DestIP:   net.ParseIP("10.1.2.3"),
		DestPort: 9000,
	})
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if decision.Action != RouteAllowDirect || decision.RuleName != "allow-app" {
		t.Fatalf("expected allow-app route decision, got %#v", decision)
	}
	want := L4Match{EndpointProtocol: "tcp", DestPort: 9000, PortRange: PortRange{Start: 8443, End: 9443}, Kind: L4MatchRange}
	if decision.MatchedL4 == nil {
		t.Fatalf("expected l4 match %#v, got nil", want)
	}
	if *decision.MatchedL4 != want {
		t.Fatalf("expected l4 match %#v, got %#v", want, *decision.MatchedL4)
	}
}

func TestPolicyHookCarriesCredentialMetadata(t *testing.T) {
	compiled := policytest.LoadPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "header_token" "internal-api" {
  endpoint = https.api
  header = "X-Internal-Token"
  prefix = "Token "
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
}
`)

	decision, err := NewPolicyHook(compiled).DecideHTTP(context.Background(), HTTPRequest{
		EndpointKind: "https",
		Host:         "api.example.com",
		Method:       http.MethodGet,
	})
	if err != nil {
		t.Fatalf("DecideHTTP returned error: %v", err)
	}
	if decision.Credential == nil {
		t.Fatalf("expected credential metadata, got %#v", decision)
	}
	if decision.Credential.Kind != "header_token" || decision.Credential.Name != "internal-api" || decision.Credential.Header != "X-Internal-Token" || decision.Credential.Prefix != "Token " {
		t.Fatalf("unexpected credential metadata: %#v", decision.Credential)
	}
}

func TestPolicyHookCarriesPackageFacetMetadata(t *testing.T) {
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "settings": {"default_action": "deny", "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": "https://intelligence.example.com"},
    "egress": [{"host": "intelligence.example.com", "port": 443, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }],
  "rules": [{"name": "allow-old", "endpoints": ["public"], "condition": "package.age_hours >= 24", "verdict": "allow"}]
}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := NewPolicyHook(compiled).DecideAction(context.Background(), "registries", "public", FacetValues{
		"http": {
			"method": http.MethodGet, "host": "registry.npmjs.org", "path": "/example", "query": map[string][]string{}, "headers": map[string][]string{},
		},
		"package": {
			"ecosystem": "npm", "operation": "download", "name": "example", "version": "1.0.0", "identity_known": true,
			"age_known": true, "age_hours": int64(48), "age_source": "registry", "malware_data_available": true, "malware": false, "malware_reason": "",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != RouteAllowDirect || decision.RuleName != "allow-old" || decision.Package == nil {
		t.Fatalf("unexpected package decision: %#v", decision)
	}
	if decision.Package.Name != "example" || decision.Package.Version != "1.0.0" || decision.Package.AgeHours != 48 || decision.Package.AgeSource != "registry" {
		t.Fatalf("unexpected package metadata: %#v", decision.Package)
	}
}
