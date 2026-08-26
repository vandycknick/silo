package silo

const defaultRuntimeReleaseOrigin = "https://github.com/vandycknick/silo/releases/download"

type runtimeArchiveMetadata struct {
	version string
	target  RuntimeTarget
	name    string
	sha256  string
}

// Digests are populated by the release preparation flow from qualified native archives.
// Empty development digests deliberately disable default and local installation rather than
// weakening exact-version verification.
var runtimeArchives = map[RuntimeTarget]runtimeArchiveMetadata{
	RuntimeTargetDarwinARM64: {
		version: Version,
		target:  RuntimeTargetDarwinARM64,
		name:    "silo-runtime-" + Version + "-darwin-arm64.tar.zst",
	},
	RuntimeTargetLinuxAMD64GNU: {
		version: Version,
		target:  RuntimeTargetLinuxAMD64GNU,
		name:    "silo-runtime-" + Version + "-linux-amd64-gnu.tar.zst",
	},
	RuntimeTargetLinuxARM64GNU: {
		version: Version,
		target:  RuntimeTargetLinuxARM64GNU,
		name:    "silo-runtime-" + Version + "-linux-arm64-gnu.tar.zst",
	},
}
