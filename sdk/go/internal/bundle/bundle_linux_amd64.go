//go:build linux && amd64

package bundle

const (
	platformSupported = true
	platformTarget    = "linux-amd64-gnu"
	platformFilename  = "libsilo_go_ffi.so"
	embeddedDigest    = ""
)

var embeddedLibrary []byte
