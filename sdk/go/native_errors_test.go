package silo

import (
	"errors"
	"testing"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

func TestUnknownNativeErrorPreservesVariant(t *testing.T) {
	err := fromNativeError(&ffi.NativeError{Variant: "FutureVariant", Message: "future failure"})
	var siloError *Error
	if !errors.As(err, &siloError) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if siloError.Kind != ErrorUnknown || siloError.NativeVariant != "FutureVariant" || siloError.Message != "future failure" {
		t.Fatalf("mapped error = %#v", siloError)
	}
}
