package silo

import (
	"context"
	"os"
	"testing"
)

func TestOpenRejectsCancelledContextBeforeLoadingBridge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Open(ctx)
	if !IsErrorKind(err, ErrorCancelled) {
		t.Fatalf("Open() error = %v, want ErrorCancelled", err)
	}
}

func TestOpenRejectsBlankRuntimePathBeforeLoadingBridge(t *testing.T) {
	_, err := Open(context.Background(), WithRuntimeRoot("   "))
	if !IsErrorKind(err, ErrorInvalidArgument) {
		t.Fatalf("Open() error = %v, want ErrorInvalidArgument", err)
	}
}

func TestOpenRealBridgeReportsMissingRuntime(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	root := t.TempDir()
	_, err := Open(context.Background(), WithDataRoot(root), WithRuntimeRoot(root))
	if err == nil {
		t.Fatal("Open() unexpectedly succeeded with an empty runtime root")
	}
	if !IsErrorKind(err, ErrorRuntimeComponentInvalid) {
		t.Fatalf("Open() error = %v, want ErrorRuntimeComponentInvalid", err)
	}
}
