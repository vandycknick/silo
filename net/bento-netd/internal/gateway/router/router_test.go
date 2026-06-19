package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/audit"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy"
)

func TestDecideWritesFlowAuditRecord(t *testing.T) {
	compiled := loadRouterPolicy(t, `
endpoint "ip" "web" {
  destination = ["203.0.113.10/32"]
  protocol = "tcp"
  ports = [443]
}

rule "deny-web" {
  endpoint = ip.web
  verdict = "deny"
  reason = "blocked"
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	flow := hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 49152,
		DestIP:     net.ParseIP("203.0.113.10"),
		DestPort:   443,
		VMID:       "vm-123",
		NetworkID:  "net-456",
	}
	route := New(hooks.NewPolicyHook(compiled), auditLog)

	if _, err := route.Decide(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.FinalAction != hooks.RouteDeny {
		t.Fatalf("expected deny audit action, got %q", event.FinalAction)
	}
	if event.Layer != "flow" || event.Source != "rule" || event.DefaultAction != "allow" || event.ClassificationOpportunity {
		t.Fatalf("unexpected audit decision source metadata: %#v", event)
	}
	if event.RuleName != "deny-web" || event.EndpointKind != "ip" || event.EndpointName != "web" {
		t.Fatalf("unexpected audit decision metadata: %#v", event)
	}
	if event.Protocol != "tcp" || event.SourceIP != "192.168.127.2" || event.SourcePort != 49152 || event.DestIP != "203.0.113.10" || event.DestPort != 443 {
		t.Fatalf("unexpected audit flow metadata: %#v", event)
	}
	if event.VMID != "vm-123" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected audit runtime metadata: %#v", event)
	}
}

func TestDecideHTTPWritesRequestAuditRecord(t *testing.T) {
	compiled := loadRouterPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "https" "api" {
  hosts = ["api.example.test"]
}

rule "allow-api" {
  endpoint = https.api
  verdict = "allow"
  reason = "allowed"
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	request := hooks.HTTPRequest{
		Flow: hooks.Flow{
			Protocol:   "tcp",
			SourceIP:   net.ParseIP("192.168.127.2"),
			SourcePort: 49153,
			DestIP:     net.ParseIP("198.51.100.20"),
			DestPort:   443,
			VMID:       "vm-123",
			NetworkID:  "net-456",
		},
		EndpointKind: "https",
		Host:         "api.example.test",
		Method:       http.MethodPost,
		Path:         "/v1/messages",
	}
	route := New(hooks.NewPolicyHook(compiled), auditLog)

	if _, err := route.DecideHTTP(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.FinalAction != hooks.RouteAllowDirect {
		t.Fatalf("expected allow audit action, got %q", event.FinalAction)
	}
	if event.Layer != "request" || event.Source != "rule" || event.DefaultAction != "deny" || event.ClassificationOpportunity {
		t.Fatalf("unexpected audit decision source metadata: %#v", event)
	}
	if event.RuleName != "allow-api" || event.EndpointKind != "https" || event.EndpointName != "api" {
		t.Fatalf("unexpected audit decision metadata: %#v", event)
	}
	if event.HTTPMethod != http.MethodPost || event.HTTPHost != "api.example.test" || event.HTTPPath != "/v1/messages" {
		t.Fatalf("unexpected audit HTTP metadata: %#v", event)
	}
	if event.Protocol != "tcp" || event.SourcePort != 49153 || event.DestPort != 443 {
		t.Fatalf("unexpected audit flow metadata: %#v", event)
	}
}

func readAuditEvent(t *testing.T, path string) audit.Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var event audit.Event
	if err := json.NewDecoder(file).Decode(&event); err != nil {
		t.Fatal(err)
	}
	return event
}

func loadRouterPolicy(t *testing.T, text string) *policy.Policy {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "policy.hcl")
	if err := os.WriteFile(policyPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	return compiled
}
