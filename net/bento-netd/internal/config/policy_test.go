package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
)

func TestLoadPolicyFileParsesCIDRRulesAndAuditPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{
  "default_action": "allow",
  "audit_log": {"enabled": true, "path": "/tmp/audit.jsonl"},
  "cidr_rules": [{
    "name": "deny-private",
    "action": "deny",
    "dest_cidrs": ["10.0.0.0/8"],
    "protocols": ["tcp"],
    "reason": "private blocked"
  }]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	policy, auditLog, err := loadPolicyFile(path)
	if err != nil {
		t.Fatalf("loadPolicyFile returned error: %v", err)
	}
	if auditLog != "/tmp/audit.jsonl" {
		t.Fatalf("expected audit path, got %q", auditLog)
	}
	if policy.DefaultAction != hooks.RouteAllowDirect {
		t.Fatalf("expected default allow, got %s", policy.DefaultAction)
	}
	if len(policy.CIDRRules) != 1 {
		t.Fatalf("expected one rule, got %d", len(policy.CIDRRules))
	}
	if policy.CIDRRules[0].Action != hooks.RouteDeny {
		t.Fatalf("expected deny rule, got %s", policy.CIDRRules[0].Action)
	}
}

func TestLoadPolicyFileRejectsObserveAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{
  "default_action": "allow",
  "cidr_rules": [{
    "name": "observe-private",
    "action": "observe",
    "dest_cidrs": ["10.0.0.0/8"]
  }]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := loadPolicyFile(path); err == nil {
		t.Fatal("expected observe action to be rejected")
	}
}
