package silo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

func nativeAttachmentMachine(t *testing.T) *Machine {
	t.Helper()
	runtime, home := phase7Runtime(t)
	disk := filepath.Join(home, "attachment.raw")
	if err := os.WriteFile(disk, []byte("stopped-native-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	machine, err := runtime.CreateMachine(context.Background(), DiskImage(disk), WithName("attachment-native"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = machine.Close() })
	return machine
}

// These exercise real exported C operations and bounded Tokio pipes. No guest
// response or native operation is substituted; the stopped VM is never started.
func TestNativeShellAttachmentCancellationWakesEveryBoundedDirection(t *testing.T) {
	machine := nativeAttachmentMachine(t)
	token, err := ffi.NewAttachmentCancellation()
	if err != nil {
		t.Fatal(err)
	}
	remaining := 0
	// A failed wakeup must not free a pointer still borrowed by a cgo operation.
	defer func() {
		if remaining == 0 {
			token.Close()
		}
	}()
	attachment, err := machine.native.NewSshAttachment(token, 37, 119)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if remaining == 0 {
			attachment.Close()
		}
	}()
	if err := attachment.Write(make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}
	for range 64 {
		if err := attachment.Resize(37, 119); err != nil {
			t.Fatal(err)
		}
	}
	finished := make(chan error, 4)
	remaining = 4
	go func() { finished <- attachment.Write([]byte{1}) }()
	go func() { _, _, err := attachment.Read(false); finished <- err }()
	go func() { _, _, err := attachment.Read(true); finished <- err }()
	go func() { finished <- attachment.Resize(38, 120) }()
	select {
	case err := <-finished:
		remaining--
		t.Errorf("bounded operation completed before cancel: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := attachment.Cancel(); err != nil {
		t.Errorf("cancel: %v", err)
		_ = token.Cancel()
	}
	for remaining > 0 {
		select {
		case err := <-finished:
			remaining--
			if !IsErrorKind(fromNativeError(err), ErrorCancelled) {
				t.Errorf("cancel wakeup: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("native operation did not join after cancellation")
		}
	}
	if err := attachment.Write(nil); !IsErrorKind(fromNativeError(err), ErrorCancelled) {
		t.Fatalf("cancellation not sticky: %v", err)
	}
}

func TestNativeShellAttachmentValidatesIdentityAndSingleConsumption(t *testing.T) {
	machine := nativeAttachmentMachine(t)
	token, err := ffi.NewAttachmentCancellation()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	other, err := ffi.NewAttachmentCancellation()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := machine.native.NewSshAttachment(token, 0, 119); !IsErrorKind(fromNativeError(err), ErrorInvalidArgument) {
		t.Fatalf("dimensions: %v", err)
	}
	attachment, err := machine.native.NewSshAttachment(token, 37, 119)
	if err != nil {
		t.Fatal(err)
	}
	defer attachment.Close()
	request := []byte(`{"env":{}}`)
	if _, err := machine.native.Shell(request, other, attachment); !IsErrorKind(fromNativeError(err), ErrorInvalidArgument) {
		t.Fatalf("token mismatch: %v", err)
	}
	if err := token.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.native.Shell(request, token, attachment); !IsErrorKind(fromNativeError(err), ErrorCancelled) {
		t.Fatalf("pre-start cancellation: %v", err)
	}
	if _, err := machine.native.Shell(request, token, attachment); !IsErrorKind(fromNativeError(err), ErrorInvalidArgument) {
		t.Fatalf("duplicate consumption: %v", err)
	}
}
