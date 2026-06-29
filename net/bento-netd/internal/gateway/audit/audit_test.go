package audit

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
)

const testPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOpenAppendsAuditJSONL(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	for range 2 {
		logger, err := Open(auditPath, testPolicyHash)
		if err != nil {
			t.Fatal(err)
		}
		logger.RecordFlow(testFlow(), testDenyDecision())
		if err := logger.Close(); err != nil {
			t.Fatal(err)
		}
	}

	rawAudit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(rawAudit, []byte("\n")); got != 2 {
		t.Fatalf("expected two JSONL records, got %d in %s", got, rawAudit)
	}
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected audit file mode 0600, got %o", got)
	}
}

func TestOpenOmitsPolicyHashWhenUnset(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := Open(auditPath, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.RecordFlow(testFlow(), testDenyDecision())
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	rawAudit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawAudit), "policy_hash") {
		t.Fatalf("expected policy_hash to be omitted for implicit default policy, got %s", rawAudit)
	}
}

func TestWriteFailureIsLoggedAndDoesNotDisableSink(t *testing.T) {
	logs := captureAuditLogs(t)
	logger := newLogger(errorWriter{}, nil, testPolicyHash, 2)
	logger.RecordFlow(testFlow(), testDenyDecision())
	logger.RecordFlow(testFlow(), testDenyDecision())
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	logText := logs.String()
	if got := strings.Count(logText, "audit write failed"); got != 2 {
		t.Fatalf("expected both write failures to be logged, got %d in %q", got, logText)
	}
}

func TestFullQueueDropsAndLogs(t *testing.T) {
	logs := captureAuditLogs(t)
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	logger := newLogger(writer, nil, testPolicyHash, 1)

	logger.RecordFlow(testFlow(), testDenyDecision())
	<-writer.started
	logger.RecordFlow(testFlow(), testDenyDecision())
	logger.RecordFlow(testFlow(), testDenyDecision())
	close(writer.release)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	logText := logs.String()
	if !strings.Contains(logText, "audit event dropped") {
		t.Fatalf("expected queue drop to be logged, got %q", logText)
	}
}

func TestRedactedHeadersOnlyRedactsSensitiveHeaders(t *testing.T) {
	headers := http.Header{
		"Accept":        {"application/json"},
		"Authorization": {"Bearer secret"},
		"Cookie":        {"session=secret"},
		"User-Agent":    {"curl/8.7.1"},
		"X-Api-Key":     {"secret-key"},
	}

	redacted := redactedHeaders(headers)
	if got := redacted["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("expected Accept to be preserved, got %#v", redacted)
	}
	if got := redacted["User-Agent"]; len(got) != 1 || got[0] != "curl/8.7.1" {
		t.Fatalf("expected User-Agent to be preserved, got %#v", redacted)
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if got := redacted[name]; len(got) != 1 || got[0] != redactedHeaderValue {
			t.Fatalf("expected %s to be redacted, got %#v", name, redacted)
		}
	}
}

func captureAuditLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func testFlow() hooks.Flow {
	return hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 49152,
		DestIP:     net.ParseIP("203.0.113.10"),
		DestPort:   443,
		VMID:       "vm-123",
		NetworkID:  "net-456",
	}
}

func testDenyDecision() hooks.RouteDecision {
	return hooks.RouteDecision{
		Action:        hooks.RouteDeny,
		Layer:         "flow",
		Source:        "default",
		DefaultAction: "deny",
		Reason:        "default_deny",
	}
}
