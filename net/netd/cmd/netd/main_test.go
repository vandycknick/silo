package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/logfile"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"golang.org/x/sys/unix"
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

func TestOpenAuditLogUsesExplicitPath(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	directory := testDirectory(t, dir)

	auditLog, err := openAuditLog(directory, "audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if auditLog == nil {
		t.Fatal("expected audit log file")
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditLog(directory, ""); err == nil {
		t.Fatal("expected an empty explicit audit path to be rejected")
	}
}

func TestConfigureLoggingAppendsToExistingServiceLog(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "netd.log")
	directory := testDirectory(t, dir)
	if err := os.WriteFile(logFile, []byte("old log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := configureLogging(directory, "netd.log")
	if err != nil {
		t.Fatal(err)
	}
	slog.Info("new log")
	if err := closeServiceLog(file); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected log file mode 0600, got %o", got)
	}
	contents, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(contents), "old log\n") || !strings.Contains(string(contents), `"msg":"new log"`) {
		t.Fatalf("expected retained and appended service logs, got %q", contents)
	}
}

func testDirectory(t *testing.T, path string) *logfile.Directory {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := logfile.OpenDirectory(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	return directory
}

func TestSecureEndpointRequiresAnOwnedPrivateSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "netd-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "netd.sock")
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := secureEndpoint("unixgram://" + path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %04o, want 0600", got)
	}

	regular := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureEndpoint("unixgram://" + regular); err == nil {
		t.Fatal("expected regular file endpoint to be rejected")
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
