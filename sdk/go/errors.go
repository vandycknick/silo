package silo

import "errors"

// ErrorKind identifies a stable Silo SDK error category.
type ErrorKind string

const (
	ErrorUnknown                     ErrorKind = "Unknown"
	ErrorInvalidArgument             ErrorKind = "InvalidArgument"
	ErrorClosed                      ErrorKind = "Closed"
	ErrorCancelled                   ErrorKind = "Cancelled"
	ErrorFFILoad                     ErrorKind = "FfiLoad"
	ErrorABIMismatch                 ErrorKind = "AbiMismatch"
	ErrorUnsupportedTarget           ErrorKind = "UnsupportedTarget"
	ErrorRuntimeReleaseUnavailable   ErrorKind = "RuntimeReleaseUnavailable"
	ErrorArchiveIntegrity            ErrorKind = "ArchiveIntegrity"
	ErrorInstallation                ErrorKind = "Installation"
	ErrorDataDirUnavailable          ErrorKind = "DataDirUnavailable"
	ErrorStateDirUnavailable         ErrorKind = "StateDirUnavailable"
	ErrorConfigDirUnavailable        ErrorKind = "ConfigDirUnavailable"
	ErrorRelativeEnvironmentPath     ErrorKind = "RelativeEnvironmentPath"
	ErrorInvalidRunRoot              ErrorKind = "InvalidRunRoot"
	ErrorInvalidOwnedPath            ErrorKind = "InvalidOwnedPath"
	ErrorInvalidMachineName          ErrorKind = "InvalidMachineName"
	ErrorInvalidMachineIDPrefix      ErrorKind = "InvalidMachineIdPrefix"
	ErrorMachineAlreadyExists        ErrorKind = "MachineAlreadyExists"
	ErrorMachineNameGenerationFailed ErrorKind = "MachineNameGenerationFailed"
	ErrorMachineNotFound             ErrorKind = "MachineNotFound"
	ErrorImageNotFound               ErrorKind = "ImageNotFound"
	ErrorImageInUse                  ErrorKind = "ImageInUse"
	ErrorImagePullPolicyUnsupported  ErrorKind = "ImagePullPolicyUnsupported"
	ErrorLocalDiskCanonicalize       ErrorKind = "LocalDiskCanonicalize"
	ErrorLocalDiskMetadata           ErrorKind = "LocalDiskMetadata"
	ErrorLocalDiskNotRegularFile     ErrorKind = "LocalDiskNotRegularFile"
	ErrorLocalDiskUnreadable         ErrorKind = "LocalDiskUnreadable"
	ErrorImage                       ErrorKind = "Image"
	ErrorMachineIDAlreadyExists      ErrorKind = "MachineIdAlreadyExists"
	ErrorMachineAlreadyRunning       ErrorKind = "MachineAlreadyRunning"
	ErrorMachineNotRunning           ErrorKind = "MachineNotRunning"
	ErrorMachineStaleGeneration      ErrorKind = "MachineStaleGeneration"
	ErrorMachineLogSourceUnavailable ErrorKind = "MachineLogSourceUnavailable"
	ErrorMonitorConnection           ErrorKind = "MonitorConnection"
	ErrorMonitorProtocol             ErrorKind = "MonitorProtocol"
	ErrorGuestSession                ErrorKind = "GuestSession"
	ErrorMachinePreparationFailed    ErrorKind = "MachinePreparationFailed"
	ErrorMachineStartCleanupFailed   ErrorKind = "MachineStartCleanupFailed"
	ErrorEntrypointLaunchFailed      ErrorKind = "EntrypointLaunchFailed"
	ErrorNetworkRuntime              ErrorKind = "NetworkRuntime"
	ErrorVMMonExecutableNotFound     ErrorKind = "VmMonExecutableNotFound"
	ErrorVMMonExecutableInvalid      ErrorKind = "VmMonExecutableInvalid"
	ErrorRuntimeComponentInvalid     ErrorKind = "RuntimeComponentInvalid"
	ErrorRuntimeComponentsNotFound   ErrorKind = "RuntimeComponentsNotFound"
	ErrorBootAssetNotFound           ErrorKind = "BootAssetNotFound"
	ErrorBootAssetInvalid            ErrorKind = "BootAssetInvalid"
	ErrorInvalidCreateRequest        ErrorKind = "InvalidCreateRequest"
	ErrorInvalidMachineUpdate        ErrorKind = "InvalidMachineUpdate"
	ErrorInvalidMachineConfig        ErrorKind = "InvalidMachineConfig"
	ErrorUnsupportedHostArchitecture ErrorKind = "UnsupportedHostArchitecture"
	ErrorCorruptState                ErrorKind = "CorruptState"
	ErrorVMSpecSerializeFailed       ErrorKind = "VmSpecSerializeFailed"
	ErrorVMSpecLoadFailed            ErrorKind = "VmSpecLoadFailed"
	ErrorAmbiguousIDPrefix           ErrorKind = "AmbiguousIdPrefix"
	ErrorStateDecode                 ErrorKind = "StateDecode"
	ErrorStateDatabaseConfigMismatch ErrorKind = "StateDatabaseConfigMismatch"
	ErrorDatabase                    ErrorKind = "Database"
	ErrorDatabaseMigration           ErrorKind = "DatabaseMigration"
	ErrorIO                          ErrorKind = "Io"
	ErrorRootDisk                    ErrorKind = "RootDisk"
)

// Error is a typed SDK or native libvm failure.
type Error struct {
	Kind          ErrorKind
	NativeVariant string
	Message       string
	cause         error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

// Unwrap returns an underlying standard error, such as context.Canceled, when present.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is compares Silo errors by kind. A target with an empty kind matches every Silo error.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && (other.Kind == "" || e.Kind == other.Kind)
}

// IsErrorKind reports whether err or an error in its chain has the requested Silo kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var siloError *Error
	return errors.As(err, &siloError) && siloError.Kind == kind
}

func newError(kind ErrorKind, nativeVariant, message string) *Error {
	return &Error{Kind: kind, NativeVariant: nativeVariant, Message: message}
}
