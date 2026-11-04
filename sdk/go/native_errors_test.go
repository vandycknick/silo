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

func TestLiveCapabilitiesNativeErrorKinds(t *testing.T) {
	for variant, kind := range map[string]ErrorKind{
		"LiveOperationUnsupported": ErrorLiveOperationUnsupported,
		"LiveDiscovery":            ErrorLiveDiscovery,
		"LiveProtocol":             ErrorLiveProtocol,
		"LiveObservation":          ErrorLiveObservation,
	} {
		var converted *Error
		if !errors.As(fromNativeError(&ffi.NativeError{Variant: variant, Message: "not parsed"}), &converted) || converted.Kind != kind || converted.NativeVariant != variant {
			t.Fatalf("lost live error kind %s", variant)
		}
	}
}
