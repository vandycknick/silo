package silo

import (
	"context"
	"os"
	"testing"
)

func TestOpenRejectsInvalidInputsBeforeLoadingBridge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		context context.Context
		options []RuntimeOption
		want    ErrorKind
	}{
		{name: "cancelled context", context: ctx, want: ErrorCancelled},
		{name: "blank runtime path", context: context.Background(), options: []RuntimeOption{WithRuntimeRoot("   ")}, want: ErrorInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Open(test.context, test.options...)
			if !IsErrorKind(err, test.want) {
				t.Fatalf("Open() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOpenRealBridgeReportsMissingRuntime(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	root := t.TempDir()
	_, err := Open(context.Background(), WithHome(root), WithRuntimeRoot(root))
	if err == nil {
		t.Fatal("Open() unexpectedly succeeded with an empty runtime root")
	}
	if !IsErrorKind(err, ErrorRuntimeComponentInvalid) {
		t.Fatalf("Open() error = %v, want ErrorRuntimeComponentInvalid", err)
	}
}
