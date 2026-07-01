package router

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vandycknick/bentobox/net/netd/internal/gateway/audit"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/netd/internal/policy"
)

func TestRecordFlowWritesIPAuditRecord(t *testing.T) {
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
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
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

	decision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	route.RecordFlow(flow, decision)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.Version != 1 || event.Phase != "end" || event.Family != "ip" {
		t.Fatalf("unexpected audit envelope: %#v", event)
	}
	if event.PolicyHash != compiled.PolicyHash() || !isUUIDv7(event.FlowID) || event.ParentFlowID != "" || event.RequestID != "" {
		t.Fatalf("unexpected audit ids/hash: %#v", event)
	}
	if event.Verdict != "deny" || event.Reason != "blocked" {
		t.Fatalf("unexpected audit verdict: %#v", event)
	}
	if event.Policy == nil || event.Policy.RuleName != "deny-web" || event.Policy.EndpointKind != "ip" || event.Policy.EndpointName != "web" {
		t.Fatalf("unexpected audit decision metadata: %#v", event)
	}
	if event.Protocol != "tcp" || event.IPVersion != "ipv4" || event.SourceIP != "192.168.127.2" || event.SourcePort != 49152 || event.DestIP != "203.0.113.10" || event.DestPort != 443 {
		t.Fatalf("unexpected audit flow metadata: %#v", event)
	}
	if event.VMID != "vm-123" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected audit runtime metadata: %#v", event)
	}
	assertAuditDoesNotContain(t, auditPath, "profile_name")
	assertAuditDoesNotContain(t, auditPath, "l4_match")
	assertAuditDoesNotContain(t, auditPath, "duration_ms")
	assertAuditDoesNotContain(t, auditPath, "bytes_in")
	assertAuditDoesNotContain(t, auditPath, "bytes_out")
	assertAuditDoesNotContain(t, auditPath, "packets")
}

func TestDecideDoesNotAuditBeforeTerminalPath(t *testing.T) {
	compiled := loadRouterPolicy(t, `
settings {
  default_action = "deny"
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
	if err != nil {
		t.Fatal(err)
	}

	route := New(hooks.NewPolicyHook(compiled), auditLog)
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	if _, err := route.Decide(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoAuditRecords(t, auditPath)
}

func TestRecordFlowWritesIPv6AuditRecord(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, "")
	if err != nil {
		t.Fatal(err)
	}
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("2001:db8::10"), SourcePort: 49152, DestIP: net.ParseIP("2001:db8::20"), DestPort: 443}
	route := New(hooks.NewPolicyHook(policy.Default()), auditLog)
	decision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	route.RecordFlow(flow, decision)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.IPVersion != "ipv6" || event.SourceIP != "2001:db8::10" || event.DestIP != "2001:db8::20" {
		t.Fatalf("unexpected IPv6 audit metadata: %#v", event)
	}
	if event.PolicyHash != "" {
		t.Fatalf("implicit default policy should omit policy_hash: %#v", event)
	}
}

func TestRecordFlowWritesExplicitAllowAuditRecord(t *testing.T) {
	compiled := loadRouterPolicy(t, `
endpoint "ip" "api" {
  destination = ["203.0.113.20/32"]
  protocol = "tcp"
  ports = [443]
}

rule "allow-api" {
  endpoint = ip.api
  verdict = "allow"
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
	if err != nil {
		t.Fatal(err)
	}
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.20"), DestPort: 443}
	route := New(hooks.NewPolicyHook(compiled), auditLog)
	decision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	route.RecordFlow(flow, decision)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.Verdict != "allow" || event.Reason != "rule_allow" {
		t.Fatalf("unexpected explicit allow verdict/reason: %#v", event)
	}
	if event.Policy == nil || event.Policy.RuleName != "allow-api" || event.Policy.EndpointKind != "ip" || event.Policy.EndpointName != "api" {
		t.Fatalf("unexpected explicit allow policy metadata: %#v", event)
	}
}

func TestRecordFlowWritesClassificationHandoffAuditRecord(t *testing.T) {
	compiled := loadRouterPolicy(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
	if err != nil {
		t.Fatal(err)
	}
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("169.254.169.254"), DestPort: 80}
	route := New(hooks.NewPolicyHook(compiled), auditLog)
	decision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != hooks.RouteClassify {
		t.Fatalf("expected L7 classification handoff decision, got %#v", decision)
	}
	route.RecordFlowOutcome(flow, decision, "classify")
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.Family != "ip" || event.Phase != "end" || event.Verdict != "allow" || event.Reason != "classify" {
		t.Fatalf("unexpected classification handoff record: %#v", event)
	}
	if event.Policy != nil {
		t.Fatalf("default classification handoff should not include policy metadata: %#v", event)
	}
}

func TestRecordFlowWritesTerminalErrorMetadata(t *testing.T) {
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	tests := []struct {
		name       string
		decision   hooks.RouteDecision
		reason     string
		wantPolicy bool
	}{
		{
			name:     "before endpoint selection",
			decision: hooks.RouteDecision{Action: hooks.RouteDeny, Reason: "policy_error"},
			reason:   "policy_error",
		},
		{
			name: "after endpoint selection",
			decision: hooks.RouteDecision{
				Action:       hooks.RouteAllowDirect,
				Layer:        "flow",
				Source:       "rule",
				RuleName:     "allow-web",
				EndpointKind: "ip",
				EndpointName: "web",
			},
			reason:     "upstream_error",
			wantPolicy: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			auditLog, err := audit.Open(auditPath, "")
			if err != nil {
				t.Fatal(err)
			}
			route := New(hooks.NewPolicyHook(policy.Default()), auditLog)
			route.RecordFlowOutcome(flow, test.decision, test.reason)
			if err := auditLog.Close(); err != nil {
				t.Fatal(err)
			}

			event := readAuditEvent(t, auditPath)
			if event.Reason != test.reason || event.Error == nil || event.Error.Code != test.reason {
				t.Fatalf("unexpected terminal error metadata: %#v", event)
			}
			if (event.Policy != nil) != test.wantPolicy {
				t.Fatalf("unexpected policy metadata presence: %#v", event)
			}
		})
	}
}

func TestRecordFlowWritesTunnelMetadataWhenPresent(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, "")
	if err != nil {
		t.Fatal(err)
	}
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	decision := hooks.RouteDecision{Action: hooks.RouteAllowDirect, Tunnel: &hooks.Tunnel{Kind: "tailscale", Name: "prod"}}
	route := New(hooks.NewPolicyHook(policy.Default()), auditLog)
	route.RecordFlow(flow, decision)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readAuditEvent(t, auditPath)
	if event.Tunnel == nil || event.Tunnel.Kind != "tailscale" || event.Tunnel.Name != "prod" {
		t.Fatalf("unexpected tunnel metadata: %#v", event)
	}
}

func TestRecordFlowWritesDefaultActionAuditRecords(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		wantVerdict string
		wantReason  string
	}{
		{name: "default allow", policy: `settings { default_action = "allow" }`, wantVerdict: "allow", wantReason: "default_allow"},
		{name: "default deny", policy: `settings { default_action = "deny" }`, wantVerdict: "deny", wantReason: "default_deny"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled := loadRouterPolicy(t, test.policy)
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
			if err != nil {
				t.Fatal(err)
			}
			flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
			route := New(hooks.NewPolicyHook(compiled), auditLog)
			decision, err := route.Decide(context.Background(), flow)
			if err != nil {
				t.Fatal(err)
			}
			route.RecordFlow(flow, decision)
			if err := auditLog.Close(); err != nil {
				t.Fatal(err)
			}

			event := readAuditEvent(t, auditPath)
			if event.Phase != "end" || event.Family != "ip" || event.Verdict != test.wantVerdict || event.Reason != test.wantReason {
				t.Fatalf("unexpected default audit record: %#v", event)
			}
			if event.Policy != nil {
				t.Fatalf("default decision should not include endpoint/rule metadata: %#v", event)
			}
		})
	}
}

func TestRouterExposesHTTPAndHTTPSPortResolution(t *testing.T) {
	compiled := loadRouterPolicy(t, `
endpoint "http" "metadata" {
  hosts = ["metadata.internal:8080"]
}

endpoint "https" "proxmox" {
  hosts = ["203.0.113.10:8006"]
}
`)
	route := New(hooks.NewPolicyHook(compiled), nil)

	if !route.ShouldInterceptHTTP(8080) {
		t.Fatal("expected route to intercept configured http port 8080")
	}
	if route.ShouldInterceptHTTP(80) {
		t.Fatal("did not expect route to intercept unconfigured http port 80")
	}
	if !route.ShouldInterceptHTTPS(8006) {
		t.Fatal("expected route to intercept configured https port 8006")
	}
	if route.ShouldInterceptHTTPS(8443) {
		t.Fatal("did not expect route to intercept unconfigured https port 8443")
	}
	endpointName, authority, certHost, ok := route.ResolveHTTPSRawIP(net.ParseIP("203.0.113.10"), 8006)
	if !ok || endpointName != "proxmox" || authority != "203.0.113.10:8006" || certHost != "203.0.113.10" {
		t.Fatalf("raw IP route resolution = (%q, %q, %q, %v), want proxmox 203.0.113.10:8006 203.0.113.10 true", endpointName, authority, certHost, ok)
	}
	if !route.MatchHTTPSAuthority("203.0.113.10:8006", authority) {
		t.Fatal("expected exact raw IP authority to match")
	}
	if route.MatchHTTPSAuthority("203.0.113.10", authority) {
		t.Fatal("did not expect default-port authority to match non-default raw IP binding")
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

func assertNoAuditRecords(t *testing.T, path string) {
	t.Helper()
	rawAudit, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawAudit) != 0 {
		t.Fatalf("expected no audit records, got %s", rawAudit)
	}
}

func assertAuditDoesNotContain(t *testing.T, path string, forbidden string) {
	t.Helper()
	rawAudit, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawAudit), forbidden) {
		t.Fatalf("audit record contained %q: %s", forbidden, rawAudit)
	}
}

func isUUIDv7(value string) bool {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value)
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
