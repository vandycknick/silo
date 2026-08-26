//go:build (!linux && !darwin) || (linux && !amd64 && !arm64) || (darwin && !arm64)

package bundle

const (
	platformSupported = false
	platformTarget    = "unsupported"
	platformFilename  = ""
	embeddedDigest    = ""
)

var embeddedLibrary []byte
