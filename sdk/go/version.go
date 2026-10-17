package silo

import "github.com/vandycknick/silo/sdk/go/internal/ffi"

// Version is the exact Silo product and runtime version required by this SDK.
const Version = "0.1.0"

// NativeABIVersion is the native bridge ABI required by this SDK.
// ABI 1 is the initial, unreleased baseline for the current bridge contract.
const NativeABIVersion uint32 = 1

// VerifiedNativeABIVersion loads the exact bridge and returns its actual ABI after
// checking both ABI and product version. It never opens a runtime or starts a VM.
func VerifiedNativeABIVersion() (uint32, error) {
	if err := ffi.Load(Version, NativeABIVersion); err != nil {
		return 0, fromNativeError(err)
	}
	actual := ffi.NativeABIVersion()
	if actual == 0 {
		return 0, newError(ErrorUnsupportedTarget, "", "native bridge requires a supported CGO host")
	}
	return actual, nil
}
