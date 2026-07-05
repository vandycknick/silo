package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRejectsRemovedAuditAndProfileFlags(t *testing.T) {
	dir := t.TempDir()
	_, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--audit-log", filepath.Join(dir, "audit.jsonl"),
	})
	if err == nil {
		t.Fatal("expected removed --audit-log flag to be rejected")
	}

	_, err = Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--profile-name", "default",
	})
	if err == nil {
		t.Fatal("expected removed --profile-name flag to be rejected")
	}

	for _, flag := range []string{"--audit-path", "--audit-file", "--secret-store-file"} {
		_, err = Parse([]string{
			"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
			flag, filepath.Join(dir, "audit.jsonl"),
		})
		if err == nil {
			t.Fatalf("expected %s flag to be rejected", flag)
		}
	}
}

func TestLoadPolicyUsesDefaultPolicyWithoutHash(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := LoadPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Policy == nil {
		t.Fatal("expected policy to be loaded")
	}
	if cfg.Policy.PolicyHash() != "" {
		t.Fatalf("expected implicit default policy to omit policy hash, got %q", cfg.Policy.PolicyHash())
	}
}

func TestLoadPolicyRequiresTLSCAForHTTPSEndpoints(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeConfigPolicy(t, policyPath, `
{
  "version": 1,
  "metadata": {},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [{"kind": "https", "name": "github", "hosts": ["api.github.com"]}],
  "credentials": [],
  "rules": [{"name": "allow-github", "endpoints": ["github"], "verdict": "allow", "priority": 0, "disabled": false}],
  "tailscale": [],
  "forwards": []
}
`)

	cfg, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--policy-file", policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = LoadPolicy(cfg)
	if err == nil {
		t.Fatal("expected missing CA material to be rejected")
	}
}

func TestLoadPolicyDoesNotRequireSecretStoreForCredentials(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeConfigPolicy(t, policyPath, `
{
  "version": 1,
  "metadata": {},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [{"kind": "https", "name": "github", "hosts": ["api.github.com"]}],
  "credentials": [{"kind": "bearer_token", "name": "github", "endpoint": "github"}],
  "rules": [{"name": "allow-github", "endpoints": ["github"], "verdict": "allow", "priority": 0, "disabled": false}],
  "tailscale": [],
  "forwards": []
}
`)

	cfg, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--policy-file", policyPath,
		"--tls-ca-cert", filepath.Join(dir, "ca.pem"),
		"--tls-ca-key", filepath.Join(dir, "ca-key.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = LoadPolicy(cfg)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
}

func TestParseKeepsLogFileOnValidationError(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "netd.log")
	cfg, err := Parse([]string{"--log-file", logFile})
	if err == nil {
		t.Fatal("expected missing listen socket to be rejected")
	}
	if cfg == nil || cfg.LogFile != logFile {
		t.Fatalf("expected parser-owned log file on validation error, got %#v", cfg)
	}
}

func writeConfigPolicy(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
