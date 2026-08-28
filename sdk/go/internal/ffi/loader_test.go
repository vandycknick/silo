package ffi

import (
	"errors"
	"os"
	"testing"
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

func TestLoadRejectsABIMismatch(t *testing.T) {
	path := os.Getenv("SILO_GO_FFI_PATH")
	if path == "" {
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	err := load(path, "0.1.0", 999)
	var mismatch *ABIMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("load() error = %v, want ABIMismatchError", err)
	}
}
