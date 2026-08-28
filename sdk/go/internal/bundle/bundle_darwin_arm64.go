//go:build darwin && arm64

package bundle

const (
	platformSupported = true
	platformTarget    = "darwin-arm64"
	platformFilename  = "libsilo_go_ffi.dylib"
	embeddedDigest    = ""
)

var embeddedLibrary []byte
