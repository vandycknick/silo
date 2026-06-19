package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy"
)

func TestLogPolicyWarningsUsesServiceLogger(t *testing.T) {
	compiled := loadMainPolicy(t, `
settings {
  audit {
    body_buffer = "1KiB"
    body_storage = "4KiB"
  }
}
`)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	logPolicyWarnings(compiled)

	logLine := output.String()
	if !strings.Contains(logLine, `"msg":"policy load warning"`) {
		t.Fatalf("expected policy warning log message, got %q", logLine)
	}
	if !strings.Contains(logLine, "settings.audit.body_buffer") {
		t.Fatalf("expected warning text in service log, got %q", logLine)
	}
}

func TestOpenAuditLoggerUsesLogFileSibling(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "netd.log")

	auditLog, err := openAuditLogger(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if auditLog == nil {
		t.Fatal("expected audit logger for log file")
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	if auditPathForLogFile("") != "" {
		t.Fatal("expected empty audit path without a log file")
	}
}

func loadMainPolicy(t *testing.T, text string) *policy.Policy {
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
