package control

import (
	"context"
	"errors"
	"io"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rpcError accepts only standard rich status details. Unstructured transport
// messages can contain local paths or credentials and never reach remote users.
func rpcError(ctx context.Context, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s, ok := status.FromError(err)
	if !ok {
		return &silo.Error{Kind: silo.ErrorUnknown, Message: "daemon management unavailable"}
	}
	if s.Code() == codes.Canceled {
		return context.Canceled
	}
	if s.Code() == codes.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	for _, detail := range s.Details() {
		d, ok := detail.(*w.ErrorDetail)
		if !ok || d.Kind < 1 || d.Kind > 8 || d.Code < 1 || d.Code > 7 {
			continue
		}
		kind := nativeKind(d.GetNativeVariant())
		switch d.Code {
		case w.ErrorCode_ERROR_CODE_ALREADY_RUNNING:
			kind = silo.ErrorMachineAlreadyRunning
		case w.ErrorCode_ERROR_CODE_NOT_RUNNING:
			kind = silo.ErrorMachineNotRunning
		case w.ErrorCode_ERROR_CODE_STALE_GENERATION:
			kind = silo.ErrorMachineStaleGeneration
		case w.ErrorCode_ERROR_CODE_MONITOR_CONNECTION:
			kind = silo.ErrorMonitorConnection
		case w.ErrorCode_ERROR_CODE_ENTRYPOINT_LAUNCH_FAILED, w.ErrorCode_ERROR_CODE_COMMAND_NOT_FOUND:
			kind = silo.ErrorEntrypointLaunchFailed
		}
		if kind == silo.ErrorUnknown && d.GetNativeVariant() == "" {
			switch d.Kind {
			case w.ErrorKind_ERROR_KIND_INVALID:
				kind = silo.ErrorInvalidArgument
			case w.ErrorKind_ERROR_KIND_DUPLICATE:
				kind = silo.ErrorMachineAlreadyExists
			case w.ErrorKind_ERROR_KIND_CONFLICT:
				return &authz.Error{Code: "conflict", Message: d.SafeMessage, Exit: 5}
			case w.ErrorKind_ERROR_KIND_DENIED:
				return &authz.Error{Code: "denied", Message: d.SafeMessage, Exit: 4}
			case w.ErrorKind_ERROR_KIND_LIMIT:
				return &authz.Error{Code: "limit", Message: d.SafeMessage, Exit: 6}
			}
		}
		message := d.SafeMessage
		if message == "" {
			message = "daemon management operation failed"
		}
		return &silo.Error{Kind: kind, NativeVariant: d.GetNativeVariant(), Message: message}
	}
	switch s.Code() {
	case codes.InvalidArgument, codes.OutOfRange:
		return &silo.Error{Kind: silo.ErrorInvalidArgument, Message: "invalid management request"}
	case codes.NotFound:
		return &authz.Error{Code: "not_found", Message: "requested resource not found", Exit: 3}
	case codes.AlreadyExists, codes.FailedPrecondition, codes.Aborted:
		return &authz.Error{Code: "conflict", Message: "management request conflicts with current state", Exit: 5}
	case codes.PermissionDenied, codes.Unauthenticated:
		return &authz.Error{Code: "denied", Message: "management request denied", Exit: 4}
	case codes.ResourceExhausted:
		return &authz.Error{Code: "limit", Message: "management request exceeds a limit", Exit: 6}
	}
	return &silo.Error{Kind: silo.ErrorUnknown, Message: "daemon management unavailable"}
}
func nativeKind(variant string) silo.ErrorKind {
	switch silo.ErrorKind(variant) {
	case silo.ErrorMachineNotFound, silo.ErrorMachineAlreadyExists, silo.ErrorMachineAlreadyRunning, silo.ErrorMachineNotRunning, silo.ErrorMachineStaleGeneration, silo.ErrorInvalidMachineUpdate, silo.ErrorInvalidArgument, silo.ErrorInvalidCreateRequest, silo.ErrorInvalidMachineName, silo.ErrorImage, silo.ErrorImageNotFound, silo.ErrorMachinePreparationFailed, silo.ErrorMachineStartCleanupFailed, silo.ErrorEntrypointLaunchFailed, silo.ErrorRootDisk, silo.ErrorGuestSession, silo.ErrorNetworkRuntime, silo.ErrorMonitorConnection, silo.ErrorMachineLogSourceUnavailable, silo.ErrorCorruptState, silo.ErrorDatabase, silo.ErrorIO, silo.ErrorInvalidMachineConfig, silo.ErrorSecretResolution, silo.ErrorMissingNetworkSecrets:
		return silo.ErrorKind(variant)
	case silo.ErrorHomeUnavailable, silo.ErrorConfigDirUnavailable, silo.ErrorRelativeEnvironmentPath, silo.ErrorInvalidRunRoot, silo.ErrorInvalidOwnedPath, silo.ErrorInvalidMachineIDPrefix, silo.ErrorMachineNameGenerationFailed, silo.ErrorImageInUse, silo.ErrorImagePullPolicyUnsupported, silo.ErrorLocalDiskCanonicalize, silo.ErrorLocalDiskMetadata, silo.ErrorLocalDiskNotRegularFile, silo.ErrorLocalDiskUnreadable, silo.ErrorMachineIDAlreadyExists, silo.ErrorMonitorProtocol, silo.ErrorVMMonExecutableNotFound, silo.ErrorVMMonExecutableInvalid, silo.ErrorRuntimeComponentInvalid, silo.ErrorRuntimeComponentsNotFound, silo.ErrorBootAssetNotFound, silo.ErrorBootAssetInvalid, silo.ErrorUnsupportedHostArchitecture, silo.ErrorVMSpecSerializeFailed, silo.ErrorVMSpecLoadFailed, silo.ErrorAmbiguousIDPrefix, silo.ErrorStateDecode, silo.ErrorStateDatabaseConfigMismatch, silo.ErrorDatabaseMigration:
		return silo.ErrorKind(variant)
	default:
		return silo.ErrorUnknown
	}
}
