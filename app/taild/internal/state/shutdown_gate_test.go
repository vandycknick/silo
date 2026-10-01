package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShutdownGateRejectsRecoveryFromOlderEpisode(t *testing.T) {
	home := t.TempDir()
	gate := &ShutdownGate{}
	old := gate.Seal()
	if err := gate.Mark(home); err != nil {
		t.Fatal(err)
	}
	current := gate.Seal()
	if cleared, err := gate.Recover(home, old); err != nil || cleared || !gate.Pending() || !ShutdownPending(home) {
		t.Fatal("old cancellation reopened admission", cleared, err)
	}
	if cleared, err := gate.Recover(home, current); err != nil || !cleared || gate.Pending() || ShutdownPending(home) {
		t.Fatal("verified current recovery failed", cleared, err)
	}
}

func TestMarkerFailureDoesNotUndoMemorySeal(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "taild"), 0755); err != nil {
		t.Fatal(err)
	}
	gate := &ShutdownGate{}
	gate.Seal()
	if err := gate.Mark(home); err == nil {
		t.Fatal("nonprivate state directory was accepted")
	}
	if !gate.Pending() || ShutdownPending(home) {
		t.Fatal("memory seal lost or test did not isolate marker failure")
	}
}
