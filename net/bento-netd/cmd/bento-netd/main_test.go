package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy"
)

func TestLogPolicyDiagnosticsUsesServiceLogger(t *testing.T) {
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

	logPolicyDiagnostics(compiled)

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
	_, err := policy.LoadReader("policy.hcl", strings.NewReader(`
endpoint "invalid_endpoint" "private" {
  destination = ["10.0.0.0/8"]
}

credential "bearer_token" "api" {
  secret = "api-token"
}
`))
	if err == nil {
		t.Fatal("expected invalid policy")
	}

	var output bytes.Buffer
	writeErrorRecords(&output, err)
	records := decodeErrorRecords(t, output.String())
	expected := []errorRecord{
		{Type: "policy_error", Message: "Unsupported endpoint kind", Detail: `unsupported endpoint kind "invalid_endpoint"`, File: "policy.hcl", Line: 2, Column: 10},
		{Type: "policy_error", Message: "Unsupported argument", Detail: `An argument named "secret" is not expected here.`, File: "policy.hcl", Line: 7, Column: 3},
		{Type: "policy_error", Message: "Missing credential endpoint", Detail: `credential "bearer_token"."api" requires endpoint`, File: "policy.hcl", Line: 6, Column: 1},
	}
	if !reflect.DeepEqual(records, expected) {
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
	compiled, err := policy.LoadReader("policy.hcl", strings.NewReader(text))
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	return compiled
}
