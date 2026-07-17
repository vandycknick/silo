package router

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/policy/policytest"
)

func TestPolicyDecisionCarriesL4MatchMetadata(t *testing.T) {
	compiled := policytest.LoadPolicy(t, `
settings { default_action = "deny" }
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
	decision, err := New(compiled, nil).Decide(context.Background(), hooks.Flow{
		Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), DestIP: net.ParseIP("10.1.2.3"), DestPort: 9000,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := hooks.L4Match{EndpointProtocol: "tcp", DestPort: 9000, PortRange: hooks.PortRange{Start: 8443, End: 9443}, Kind: hooks.L4MatchRange}
	if decision.Action != hooks.RouteAllowDirect || decision.RuleName != "allow-app" || decision.MatchedL4 == nil || *decision.MatchedL4 != want {
		t.Fatalf("unexpected route decision: %#v", decision)
	}
}

func TestPolicyDecisionCarriesCredentialMetadata(t *testing.T) {
	compiled := policytest.LoadPolicy(t, `
settings { default_action = "deny" }
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
	decision, err := New(compiled, nil).DecideHTTP(context.Background(), hooks.HTTPRequest{
		EndpointKind: "https", Host: "api.example.com", Method: http.MethodGet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Credential == nil || decision.Credential.Kind != "header_token" || decision.Credential.Name != "internal-api" || decision.Credential.Header != "X-Internal-Token" || decision.Credential.Prefix != "Token " {
		t.Fatalf("unexpected credential metadata: %#v", decision.Credential)
	}
}

func TestPolicyDecisionCarriesPackageFacetMetadata(t *testing.T) {
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "settings": {"default_action": "deny", "audit": {}},
  "endpoints": [{
    "kind": "registries", "name": "public", "family": "package",
    "transport": "tls-terminate", "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": "https://intelligence.example.com"},
    "egress": [{"host": "intelligence.example.com", "port": 443, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }],
  "rules": [{"name": "allow-old", "endpoints": ["public"], "condition": "package.age_hours >= 24", "verdict": "allow"}]
}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := New(compiled, nil).DecidePackage(context.Background(), "registries", "public", policy.PackageRequest{
		Method: http.MethodGet, Host: "registry.npmjs.org", Path: "/example",
		Query: map[string][]string{}, Headers: map[string][]string{},
		Package: policy.PackageFacts{
			Ecosystem: "npm", Operation: "download", Name: "example", Version: "1.0.0", IdentityKnown: true,
			AgeKnown: true, AgeHours: 48, AgeSource: "registry", MalwareDataAvailable: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != hooks.RouteAllowDirect || decision.RuleName != "allow-old" || decision.Package == nil || decision.Package.Name != "example" || decision.Package.AgeHours != 48 {
		t.Fatalf("unexpected package decision: %#v", decision)
	}
}
