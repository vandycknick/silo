package control

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestRichNativeErrorParity(t *testing.T) {
	for _, kind := range []silo.ErrorKind{silo.ErrorLiveDiscovery, silo.ErrorLiveProtocol, silo.ErrorLiveObservation, silo.ErrorMachineNotFound, silo.ErrorMachineAlreadyExists, silo.ErrorMachineAlreadyRunning, silo.ErrorMachineNotRunning, silo.ErrorInvalidMachineUpdate, silo.ErrorInvalidCreateRequest, silo.ErrorInvalidMachineName, silo.ErrorImage, silo.ErrorImageNotFound, silo.ErrorMachinePreparationFailed, silo.ErrorMachineStartCleanupFailed, silo.ErrorEntrypointLaunchFailed, silo.ErrorRootDisk, silo.ErrorGuestSession, silo.ErrorNetworkRuntime} {
		t.Run(string(kind), func(t *testing.T) {
			variant := string(kind)
			s, e := status.New(codes.InvalidArgument, "unsafe /home/private secret").WithDetails(&w.ErrorDetail{Kind: w.ErrorKind_ERROR_KIND_INVALID, Code: w.ErrorCode_ERROR_CODE_NATIVE, NativeVariant: &variant, SafeMessage: "safe failure"})
			if e != nil {
				t.Fatal(e)
			}
			err := rpcError(context.Background(), s.Err())
			var got *silo.Error
			if !errors.As(err, &got) || got.NativeVariant != variant {
				t.Fatalf("native variant lost: %v", err)
			}
			if !silo.IsErrorKind(err, kind) || err.Error() != "safe failure" {
				t.Fatalf("%s: %v", kind, err)
			}
		})
	}
}

func TestRichImageReferenceRejected(t *testing.T) {
	const message = `image "docker.io/nixos/nix:latest" is denied by registry policy rule "docker.io"`
	variant, reference := "ImageReferenceRejected", "nixos/nix"
	s, err := status.New(codes.InvalidArgument, "unsafe diagnostic").WithDetails(&w.ErrorDetail{
		Kind: w.ErrorKind_ERROR_KIND_INVALID, Code: w.ErrorCode_ERROR_CODE_NATIVE,
		NativeVariant: &variant, SafeMessage: message, Reference: &reference,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got *silo.Error
	if err := rpcError(context.Background(), s.Err()); !errors.As(err, &got) || got.Kind != silo.ErrorImageReferenceRejected || got.Message != message {
		t.Fatalf("image rejection was not preserved: %v", err)
	}
}
func TestRichCodeAndTransportSemantics(t *testing.T) {
	for code, kind := range map[w.ErrorCode]silo.ErrorKind{w.ErrorCode_ERROR_CODE_ALREADY_RUNNING: silo.ErrorMachineAlreadyRunning, w.ErrorCode_ERROR_CODE_NOT_RUNNING: silo.ErrorMachineNotRunning, w.ErrorCode_ERROR_CODE_STALE_GENERATION: silo.ErrorMachineStaleGeneration, w.ErrorCode_ERROR_CODE_MONITOR_CONNECTION: silo.ErrorMonitorConnection, w.ErrorCode_ERROR_CODE_ENTRYPOINT_LAUNCH_FAILED: silo.ErrorEntrypointLaunchFailed, w.ErrorCode_ERROR_CODE_COMMAND_NOT_FOUND: silo.ErrorEntrypointLaunchFailed} {
		s, e := status.New(codes.Unavailable, "unsafe").WithDetails(&w.ErrorDetail{Kind: w.ErrorKind_ERROR_KIND_UNAVAILABLE, Code: code, SafeMessage: "safe"})
		if e != nil {
			t.Fatal(e)
		}
		if !silo.IsErrorKind(rpcError(context.Background(), s.Err()), kind) {
			t.Fatal(code)
		}
	}
	for _, err := range []error{status.Error(codes.Unknown, "secret /home/private"), errors.New("secret /home/private")} {
		got := rpcError(context.Background(), err)
		if strings.Contains(got.Error(), "secret") || strings.Contains(got.Error(), "private") {
			t.Fatal("transport diagnostic leaked")
		}
	}
	for _, test := range []struct {
		code codes.Code
		want error
	}{{codes.Canceled, context.Canceled}, {codes.DeadlineExceeded, context.DeadlineExceeded}} {
		if !errors.Is(rpcError(context.Background(), status.Error(test.code, "unsafe")), test.want) {
			t.Fatal(test.code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(rpcError(ctx, status.Error(codes.Unavailable, "unsafe")), context.Canceled) {
		t.Fatal("context cancellation lost")
	}
	if rpcError(ctx, io.EOF) != io.EOF {
		t.Fatal("EOF changed")
	}
	s, e := status.New(codes.InvalidArgument, "unsafe").WithDetails(&w.ErrorDetail{Kind: 99, Code: 99, SafeMessage: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(rpcError(context.Background(), s.Err()).Error(), "secret") {
		t.Fatal("invalid detail accepted")
	}
}

func TestLiveCapabilitiesMalformedRichErrorsAreProtocolFailures(t *testing.T) {
	refusal := &w.LiveOperationUnsupported{
		Operation: new(w.LiveOperation_LIVE_OPERATION_PAUSE),
		Backend:   new(w.LiveBackend_LIVE_BACKEND_MOCK),
		Lane:      new(w.LiveLane_LIVE_LANE_NOT_APPLICABLE),
		Reason:    &w.LiveUnsupportedReason{Code: new(w.LiveReasonCode_LIVE_REASON_CODE_BACKEND_EXCLUDED)},
	}
	valid := &w.ErrorDetail{Kind: w.ErrorKind_ERROR_KIND_CONFLICT, Code: w.ErrorCode_ERROR_CODE_LIVE_OPERATION_UNSUPPORTED, LiveUnsupported: refusal}
	for _, malformed := range []*w.ErrorDetail{
		{Kind: 0, Code: 8, LiveUnsupported: refusal},
		{Kind: 99, Code: 8, LiveUnsupported: refusal},
		{Kind: 4, Code: 0, LiveUnsupported: refusal},
		{Kind: 4, Code: 99, LiveUnsupported: refusal},
		{Kind: 4, Code: w.ErrorCode_ERROR_CODE_NATIVE, NativeVariant: new("LiveOperationUnsupported"), SafeMessage: "message only"},
	} {
		for _, laterValid := range []bool{false, true} {
			s, err := status.New(codes.FailedPrecondition, "unsafe transport").WithDetails(malformed)
			if err != nil {
				t.Fatal(err)
			}
			if laterValid {
				s, err = s.WithDetails(valid)
				if err != nil {
					t.Fatal(err)
				}
			}
			got := rpcError(context.Background(), s.Err())
			if got.Error() != invalidResponse().Error() {
				t.Fatalf("malformed detail reclassified: %v", got)
			}
		}
	}
	encoded, err := anypb.New(valid)
	if err != nil {
		t.Fatal(err)
	}
	encoded.Value = []byte{0xff}
	raw := status.New(codes.FailedPrecondition, "unsafe transport").Proto()
	raw.Details = []*anypb.Any{encoded}
	if got := rpcError(context.Background(), status.FromProto(raw).Err()); got.Error() != invalidResponse().Error() {
		t.Fatalf("malformed recognized Any reclassified: %v", got)
	}
}
