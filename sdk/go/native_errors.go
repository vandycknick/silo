package silo

import (
	"errors"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

var nativeErrorKinds = map[string]ErrorKind{
	"DataDirUnavailable": ErrorDataDirUnavailable, "StateDirUnavailable": ErrorStateDirUnavailable,
	"ConfigDirUnavailable": ErrorConfigDirUnavailable, "RelativeEnvironmentPath": ErrorRelativeEnvironmentPath,
	"InvalidRunRoot": ErrorInvalidRunRoot, "InvalidOwnedPath": ErrorInvalidOwnedPath,
	"InvalidMachineName": ErrorInvalidMachineName, "InvalidMachineIdPrefix": ErrorInvalidMachineIDPrefix,
	"MachineAlreadyExists": ErrorMachineAlreadyExists, "MachineNameGenerationFailed": ErrorMachineNameGenerationFailed,
	"MachineNotFound": ErrorMachineNotFound, "ImageNotFound": ErrorImageNotFound, "ImageInUse": ErrorImageInUse,
	"ImagePullPolicyUnsupported": ErrorImagePullPolicyUnsupported, "LocalDiskCanonicalize": ErrorLocalDiskCanonicalize,
	"LocalDiskMetadata": ErrorLocalDiskMetadata, "LocalDiskNotRegularFile": ErrorLocalDiskNotRegularFile,
	"LocalDiskUnreadable": ErrorLocalDiskUnreadable, "Image": ErrorImage,
	"MachineIdAlreadyExists": ErrorMachineIDAlreadyExists, "MachineAlreadyRunning": ErrorMachineAlreadyRunning,
	"MachineNotRunning": ErrorMachineNotRunning, "MachineStaleGeneration": ErrorMachineStaleGeneration,
	"MachineLogSourceUnavailable": ErrorMachineLogSourceUnavailable, "MonitorConnection": ErrorMonitorConnection,
	"MonitorProtocol": ErrorMonitorProtocol, "GuestSession": ErrorGuestSession,
	"MachinePreparationFailed": ErrorMachinePreparationFailed, "MachineStartCleanupFailed": ErrorMachineStartCleanupFailed,
	"EntrypointLaunchFailed": ErrorEntrypointLaunchFailed, "NetworkRuntime": ErrorNetworkRuntime,
	"VmMonExecutableNotFound": ErrorVMMonExecutableNotFound, "VmMonExecutableInvalid": ErrorVMMonExecutableInvalid,
	"RuntimeComponentInvalid": ErrorRuntimeComponentInvalid, "RuntimeComponentsNotFound": ErrorRuntimeComponentsNotFound,
	"BootAssetNotFound": ErrorBootAssetNotFound, "BootAssetInvalid": ErrorBootAssetInvalid,
	"InvalidCreateRequest": ErrorInvalidCreateRequest, "InvalidMachineUpdate": ErrorInvalidMachineUpdate,
	"InvalidMachineConfig":        ErrorInvalidMachineConfig,
	"UnsupportedHostArchitecture": ErrorUnsupportedHostArchitecture, "CorruptState": ErrorCorruptState,
	"VmSpecSerializeFailed": ErrorVMSpecSerializeFailed, "VmSpecLoadFailed": ErrorVMSpecLoadFailed,
	"AmbiguousIdPrefix": ErrorAmbiguousIDPrefix, "StateDecode": ErrorStateDecode,
	"StateDatabaseConfigMismatch": ErrorStateDatabaseConfigMismatch, "Database": ErrorDatabase,
	"DatabaseMigration": ErrorDatabaseMigration, "Io": ErrorIO, "RootDisk": ErrorRootDisk,
	"InvalidArgument": ErrorInvalidArgument, "Closed": ErrorClosed,
	"Cancelled": ErrorCancelled, "InternalPanic": ErrorUnknown, "Serialization": ErrorUnknown,
}

func fromNativeError(err error) error {
	if err == nil {
		return nil
	}
	var native *ffi.NativeError
	if errors.As(err, &native) {
		kind, ok := nativeErrorKinds[native.Variant]
		if !ok {
			kind = ErrorUnknown
		}
		return newError(kind, native.Variant, native.Message)
	}
	var mismatch *ffi.ABIMismatchError
	if errors.As(err, &mismatch) {
		return newError(ErrorABIMismatch, "", mismatch.Error())
	}
	return newError(ErrorFFILoad, "", err.Error())
}
