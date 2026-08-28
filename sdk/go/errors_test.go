package silo

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestErrorMatching(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("wrapped: %w", newError(ErrorMachineNotFound, "MachineNotFound", "missing"))
	if !IsErrorKind(err, ErrorMachineNotFound) {
		t.Fatal("IsErrorKind did not find wrapped Silo error")
	}
	if !errors.Is(err, &Error{Kind: ErrorMachineNotFound}) {
		t.Fatal("errors.Is did not compare ErrorKind")
	}
	var siloError *Error
	if !errors.As(err, &siloError) {
		t.Fatal("errors.As did not find *Error")
	}
	if siloError.NativeVariant != "MachineNotFound" {
		t.Fatalf("NativeVariant = %q", siloError.NativeVariant)
	}
}

func TestContextErrorPreservesStandardCause(t *testing.T) {
	t.Parallel()
	err := contextError(context.Canceled)
	if !IsErrorKind(err, ErrorCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("context error = %v, want both Silo cancellation and context.Canceled", err)
	}
}
