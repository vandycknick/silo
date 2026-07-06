package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestLogPolicyDiagnosticsUsesServiceLogger(t *testing.T) {
	compiled := loadMainPolicy(t, `
{
  "version": 1,
  "metadata": {},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1024, "body_storage_bytes": 4096}},
  "endpoints": [],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}
`)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	logPolicyDiagnostics(compiled)

	logLine := output.String()
	if !strings.Contains(logLine, `"msg":"policy load warning"`) {
		t.Fatalf("expected policy warning log message, got %q", logLine)
	}
	if !strings.Contains(logLine, "body_buffer_bytes") {
		t.Fatalf("expected warning text in service log, got %q", logLine)
	}
}

func TestOpenAuditLoggerUsesLogFileSibling(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "netd.log")

	auditLog, err := openAuditLogger(logFile, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
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

func TestOpenLogFileTightensPermissions(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "netd.log")
	if err := os.WriteFile(logFile, []byte("old log"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(logFile, 0o644); err != nil {
		t.Fatal(err)
	}

	file, err := openLogFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected log file mode 0600, got %o", got)
	}
	if info.Size() != 0 {
		t.Fatalf("expected existing log file to be truncated, size is %d", info.Size())
	}
}

func TestReportStartupErrorWritesGenericJSONLine(t *testing.T) {
	var output bytes.Buffer
	writeErrorRecords(&output, errors.New("policy is busted"))

	var record errorRecord
	if err := json.NewDecoder(&output).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record != (errorRecord{Type: "startup_error", Message: "policy is busted"}) {
		t.Fatalf("unexpected startup error record %#v", record)
	}
}

func TestReportStartupErrorWritesPolicyJSONLines(t *testing.T) {
	_, err := policy.LoadReader("policy.json", strings.NewReader(`{
  "version": 1,
  "metadata": {},
  "settings": {"default_action": "allow", "audit": {"body_buffer_bytes": 1048576, "body_storage_bytes": 4096}},
  "endpoints": [{"kind": "invalid_endpoint", "name": "private", "destination_cidrs": ["10.0.0.0/8"]}],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}`))
	if err == nil {
		t.Fatal("expected invalid policy")
	}

	var output bytes.Buffer
	writeErrorRecords(&output, err)
	records := decodeErrorRecords(t, output.String())
	expected := []errorRecord{
		{Type: "policy_error", Message: "Invalid endpoint", Detail: `unsupported endpoint kind "invalid_endpoint"`, File: "policy.json", Line: 1, Column: 1},
	}
	if len(records) != len(expected) || records[0] != expected[0] {
		t.Fatalf("unexpected policy error records\nwant %#v\n got %#v", expected, records)
	}
}

func decodeErrorRecords(t *testing.T, text string) []errorRecord {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(text))
	var records []errorRecord
	for {
		var record errorRecord
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func loadMainPolicy(t *testing.T, text string) *policy.Policy {
	t.Helper()
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(text))
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	return compiled
}
