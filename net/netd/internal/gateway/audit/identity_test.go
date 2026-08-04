package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRecordContainsAllGenerationIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	file := openAuditFile(t, dir, "audit.jsonl")
	logger := New(file, testPolicyHash)
	logger.RecordFlow(testFlow(), testDenyDecision())
	if err := logger.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(contents, &event); err != nil {
		t.Fatal(err)
	}
	if event.VMID != "vm-123" || event.RunID != "run-789" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected audit identity: %#v", event)
	}
}

func TestAuditGenerationBoundaryContainsAllGenerationIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	file := openAuditFile(t, dir, "audit.jsonl")
	logger := New(file, testPolicyHash)
	logger.RecordGenerationBoundary("start", "vm-123", "run-789", "net-456")
	if err := logger.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(contents, &event); err != nil {
		t.Fatal(err)
	}
	if event.Family != "netd_generation" || event.Phase != "start" {
		t.Fatalf("unexpected generation boundary: %#v", event)
	}
	if event.VMID != "vm-123" || event.RunID != "run-789" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected boundary identity: %#v", event)
	}
}
