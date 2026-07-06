package hooks

import (
	"context"
	"net"
	"net/http"
	"testing"

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
