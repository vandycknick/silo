package ffi

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/vandycknick/silo/sdk/go/internal/bundle"
)

func TestLoadDevelopmentBridge(t *testing.T) {
	path := os.Getenv("SILO_GO_FFI_PATH")
	if path == "" && os.Getenv("SILO_TEST_EMBEDDED_FFI") != "1" {
		t.Skip("neither SILO_GO_FFI_PATH nor SILO_TEST_EMBEDDED_FFI is set")
	}
	if err := Load("0.1.0", 1); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
}

func TestLoadAttachmentControlSymbols(t *testing.T) {
	if err := load(actualBridgePath(t), "0.1.0", 1); err != nil {
		t.Fatal(err)
	}
	token, err := NewAttachmentCancellation()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	for _, signal := range []uint32{1, 2, 3, 15, 10, 12, 28} {
		if err = token.Signal(signal); err != nil {
			t.Fatalf("signal %d: %v", signal, err)
		}
	}
	err = token.Signal(23)
	var native *NativeError
	if !errors.As(err, &native) || native.Variant != "InvalidArgument" {
		t.Fatalf("SIGURG accepted: %v", err)
	}
	if err = token.Cancel(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsProductVersionMismatch(t *testing.T) {
	path := actualBridgePath(t)
	err := load(path, "999.0.0", 1)
	var mismatch *ABIMismatchError
	if !errors.As(err, &mismatch) || !strings.Contains(err.Error(), "version") {
		t.Fatalf("load() error = %v, want product version mismatch", err)
	}
}

func TestLoadRejectsABIMismatch(t *testing.T) {
	path := actualBridgePath(t)
	err := load(path, "0.1.0", 999)
	var mismatch *ABIMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("load() error = %v, want ABIMismatchError", err)
	}
}

func actualBridgePath(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("SILO_GO_FFI_PATH"); path != "" {
		return path
	}
	if os.Getenv("SILO_TEST_EMBEDDED_FFI") != "1" {
		t.Skip("actual bridge or qualified embedded fixture required")
	}
	path, err := bundle.Path()
	if err != nil {
		t.Fatal(err)
	}
	return path
}
