//go:build linux && arm64

package bundle

const (
	platformSupported = true
	platformTarget    = "linux-arm64-gnu"
	platformFilename  = "libsilo_go_ffi.so"
	embeddedDigest    = ""
)

var embeddedLibrary []byte
