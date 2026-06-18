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
}

func TestParseRequiresTLSCAForHTTPSEndpoints(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.hcl")
	writeConfigPolicy(t, policyPath, `
endpoint "https" "github" {
  hosts = ["api.github.com"]
}

rule "allow-github" {
  endpoint = https.github
  verdict = "allow"
}
`)

	_, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--policy-file", policyPath,
	})
	if err == nil {
		t.Fatal("expected missing CA material to be rejected")
	}
}

func TestParseRequiresSecretStoreForCredentials(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.hcl")
	writeConfigPolicy(t, policyPath, `
endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "github" {
  endpoint = https.github
}

rule "allow-github" {
  endpoint = https.github
  verdict = "allow"
}
`)

	_, err := Parse([]string{
		"--listen-vfkit", "unixgram://" + filepath.Join(dir, "net.sock"),
		"--policy-file", policyPath,
		"--tls-ca-cert", filepath.Join(dir, "ca.pem"),
		"--tls-ca-key", filepath.Join(dir, "ca-key.pem"),
	})
	if err == nil {
		t.Fatal("expected missing secret store to be rejected")
	}
}

func writeConfigPolicy(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
