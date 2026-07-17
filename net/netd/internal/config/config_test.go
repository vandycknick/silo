package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseWithoutStaticLeaseHasNoGuestLeaseOrForwards(t *testing.T) {
	cfg := parseConfig(t)
	if len(cfg.Stack.DHCPStaticLeases) != 0 {
		t.Fatalf("expected no DHCP static leases, got %#v", cfg.Stack.DHCPStaticLeases)
	}
	if len(cfg.Stack.Forwards) != 0 {
		t.Fatalf("expected no host forwards, got %#v", cfg.Stack.Forwards)
	}
}

func TestParseStaticLeaseSetsDeviceIPAndDHCPLease(t *testing.T) {
	cfg := parseConfig(t, "--static-lease", "192.168.127.42=02:00:00:00:00:2a")
	if cfg.Stack.DeviceIP != "192.168.127.42" {
		t.Fatalf("expected static lease device IP, got %q", cfg.Stack.DeviceIP)
	}
	want := map[string]string{"192.168.127.42": "02:00:00:00:00:2a"}
	if len(cfg.Stack.DHCPStaticLeases) != len(want) || cfg.Stack.DHCPStaticLeases["192.168.127.42"] != want["192.168.127.42"] {
		t.Fatalf("unexpected DHCP static leases: %#v", cfg.Stack.DHCPStaticLeases)
	}
}

func TestParseRejectsInvalidStaticLeases(t *testing.T) {
	for _, lease := range []string{
		"192.168.127.42",
		"192.168.127.42.1=02:00:00:00:00:2a",
		"192.168.127.42=02-00-00-00-00-2a",
		"192.168.127.42=02:00:00:00:00:zz",
		"192.168.127.42=02:00:00:00:00:2a:ff",
		"192.168.127.42=00:00:00:00:00:00",
		"192.168.127.42=01:00:00:00:00:2a",
		"2001:db8::42=02:00:00:00:00:2a",
		"192.168.127.0=02:00:00:00:00:2a",
		"192.168.127.1=02:00:00:00:00:2a",
		"192.168.127.254=02:00:00:00:00:2a",
		"192.168.127.255=02:00:00:00:00:2a",
		"192.168.128.42=02:00:00:00:00:2a",
	} {
		t.Run(lease, func(t *testing.T) {
			_, err := Parse(append(configArgs(t), "--static-lease", lease))
			if err == nil {
				t.Fatal("expected static lease to be rejected")
			}
		})
	}
}

func TestParseRejectsNonIPv4Subnet(t *testing.T) {
	_, err := Parse(append(configArgs(t), "--subnet", "2001:db8::/64"))
	if err == nil {
		t.Fatal("expected IPv6 subnet to be rejected")
	}
}

func TestParseRejectsRemovedSSHPortFlag(t *testing.T) {
	_, err := Parse(append(configArgs(t), "--ssh-port", "2222"))
	if err == nil {
		t.Fatal("expected removed --ssh-port flag to be rejected")
	}
}

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
	compiled, err := LoadPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if compiled == nil {
		t.Fatal("expected policy to be loaded")
	}
	if compiled.PolicyHash() != "" {
		t.Fatalf("expected implicit default policy to omit policy hash, got %q", compiled.PolicyHash())
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
  "endpoints": [{"kind": "https", "name": "github", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["api.github.com"]}],
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
	_, err = LoadPolicy(cfg)
	if err == nil {
		t.Fatal("expected missing CA material to be rejected")
	}
}

func TestLoadPolicyRequiresTLSCAForRegistryEndpoints(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeConfigPolicy(t, policyPath, `
{
  "version": 1,
  "settings": {"default_action": "allow", "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": "https://intelligence.example.com"},
    "egress": [{"host": "intelligence.example.com", "port": 443, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }]
}
`)
	cfg, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--policy-file", policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(cfg); err == nil {
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
  "endpoints": [{"kind": "https", "name": "github", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["api.github.com"]}],
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
	_, err = LoadPolicy(cfg)
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

func parseConfig(t *testing.T, args ...string) *Config {
	t.Helper()
	cfg, err := Parse(append(configArgs(t), args...))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func configArgs(t *testing.T) []string {
	t.Helper()
	return []string{"--listen-vfkit", "unixgram://" + filepath.Join(t.TempDir(), "net.sock")}
}

func writeConfigPolicy(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
