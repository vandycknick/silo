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

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/logfile"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/policy/policytest"
	"golang.org/x/sys/unix"
)

func TestRecordFlowWritesAuditEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		policy       string
		source       string
		destination  string
		port         uint16
		sharedHash   bool
		runtimeIDs   bool
		classify     bool
		tunnel       bool
		wantVerdict  string
		wantReason   string
		wantRule     string
		wantEndpoint string
	}{
		{
			name: "ip deny", source: "192.168.127.2", destination: "203.0.113.10", port: 443,
			sharedHash: true, runtimeIDs: true, wantVerdict: "deny", wantReason: "blocked", wantRule: "deny-web", wantEndpoint: "web",
			policy: `
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
`,
		},
		{name: "ipv6", source: "2001:db8::10", destination: "2001:db8::20", port: 443},
		{
			name: "explicit allow", source: "192.168.127.2", destination: "203.0.113.20", port: 443,
			wantVerdict: "allow", wantReason: "rule_allow", wantRule: "allow-api", wantEndpoint: "api",
			policy: `
endpoint "ip" "api" {
  destination = ["203.0.113.20/32"]
  protocol = "tcp"
  ports = [443]
}
rule "allow-api" {
  endpoint = ip.api
  verdict = "allow"
}
`,
		},
		{
			name: "classification handoff", source: "192.168.127.2", destination: "169.254.169.254", port: 80,
			classify: true, wantVerdict: "allow", wantReason: "classify",
			policy: `
settings {
  default_action = "deny"
}
endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`,
		},
		{name: "tunnel", source: "192.168.127.2", destination: "203.0.113.10", port: 443, tunnel: true},
		{name: "default allow", source: "192.168.127.2", destination: "203.0.113.10", port: 443, policy: `settings { default_action = "allow" }`, wantVerdict: "allow", wantReason: "default_allow"},
		{name: "default deny", source: "192.168.127.2", destination: "203.0.113.10", port: 443, policy: `settings { default_action = "deny" }`, wantVerdict: "deny", wantReason: "default_deny"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled := policy.Default()
			hash := ""
			if test.policy != "" {
				compiled = loadRouterPolicy(t, test.policy)
				hash = compiled.PolicyHash()
			}
			if test.sharedHash {
				hash = "sha256:shared-sink-default"
			}
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			auditLog := testAuditLogger(t, auditPath, hash)
			flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP(test.source), SourcePort: 49152, DestIP: net.ParseIP(test.destination), DestPort: test.port}
			if test.runtimeIDs {
				flow.VMID, flow.NetworkID = "vm-123", "net-456"
			}
			route := New(compiled, auditLog)
			var decision hooks.RouteDecision
			if test.tunnel {
				decision = hooks.RouteDecision{Action: hooks.RouteAllowDirect, Tunnel: &hooks.Tunnel{Kind: "tailscale", Name: "prod"}}
			} else {
				var err error
				decision, err = route.Decide(context.Background(), flow)
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.classify {
				if decision.Action != hooks.RouteClassify {
					t.Fatalf("expected L7 classification handoff decision, got %#v", decision)
				}
				route.RecordFlowOutcome(flow, decision, "classify")
			} else {
				route.RecordFlow(flow, decision)
			}
			if err := auditLog.Close(); err != nil {
				t.Fatal(err)
			}
			event := readAuditEvent(t, auditPath)
			if test.wantVerdict != "" && (event.Verdict != test.wantVerdict || event.Reason != test.wantReason) {
				t.Fatalf("unexpected audit verdict/reason: %#v", event)
			}
			if test.wantRule != "" {
				if event.Policy == nil || event.Policy.RuleName != test.wantRule || event.Policy.EndpointKind != "ip" || event.Policy.EndpointName != test.wantEndpoint {
					t.Fatalf("unexpected audit decision metadata: %#v", event)
				}
			} else if test.policy != "" && event.Policy != nil {
				t.Fatalf("default decision should not include policy metadata: %#v", event)
			}
			if test.runtimeIDs || test.classify || strings.HasPrefix(test.name, "default ") {
				if event.Phase != "end" || event.Family != "ip" {
					t.Fatalf("unexpected audit envelope: %#v", event)
				}
			}
			if test.runtimeIDs {
				if event.Version != 1 || event.PolicyHash != compiled.PolicyHash() || !isUUIDv7(event.FlowID) || event.ParentFlowID != "" || event.RequestID != "" {
					t.Fatalf("unexpected audit ids/hash/envelope: %#v", event)
				}
				if event.Protocol != "tcp" || event.IPVersion != "ipv4" || event.SourceIP != test.source || event.SourcePort != 49152 || event.DestIP != test.destination || event.DestPort != test.port {
					t.Fatalf("unexpected audit flow metadata: %#v", event)
				}
				if event.VMID != "vm-123" || event.NetworkID != "net-456" {
					t.Fatalf("unexpected audit runtime metadata: %#v", event)
				}
				for _, field := range []string{"profile_name", "l4_match", "duration_ms", "bytes_in", "bytes_out", "packets"} {
					assertAuditDoesNotContain(t, auditPath, field)
				}
			}
			if test.name == "ipv6" {
				if event.IPVersion != "ipv6" || event.SourceIP != test.source || event.DestIP != test.destination {
					t.Fatalf("unexpected IPv6 audit metadata: %#v", event)
				}
				if event.PolicyHash != "" {
					t.Fatalf("implicit default policy should omit policy_hash: %#v", event)
				}
			}
			if test.tunnel && (event.Tunnel == nil || event.Tunnel.Kind != "tailscale" || event.Tunnel.Name != "prod") {
				t.Fatalf("unexpected tunnel metadata: %#v", event)
			}
		})
	}
}

func TestDecideDoesNotAuditBeforeTerminalPath(t *testing.T) {
	t.Parallel()
	compiled := loadRouterPolicy(t, `
settings {
  default_action = "deny"
}
`)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog := testAuditLogger(t, auditPath, compiled.PolicyHash())

	route := New(compiled, auditLog)
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 49152, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	if _, err := route.Decide(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoAuditRecords(t, auditPath)

}

func TestRecordFlowWritesTerminalErrorMetadata(t *testing.T) {
	t.Parallel()
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
			auditLog := testAuditLogger(t, auditPath, "")
			route := New(policy.Default(), auditLog)
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

func TestRouterExposesHTTPAndHTTPSPortResolution(t *testing.T) {
	t.Parallel()
	compiled := loadRouterPolicy(t, `
endpoint "http" "metadata" {
  hosts = ["metadata.internal:8080"]
}

endpoint "https" "proxmox" {
  hosts = ["203.0.113.10:8006"]
}
`)
	route := New(compiled, nil)

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

func testAuditLogger(t *testing.T, path, policyHash string) *audit.Logger {
	t.Helper()
	directoryPath := filepath.Dir(path)
	if err := os.Chmod(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := logfile.OpenDirectory(fd)
	if err != nil {
		t.Fatal(err)
	}
	file, err := directory.OpenAppend(filepath.Base(path))
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	logger := audit.New(file, policyHash)
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Error(err)
		}
		if err := file.Close(); err != nil {
			t.Error(err)
		}
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	return logger
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
	return policytest.LoadPolicy(t, text)
}
