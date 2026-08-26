package silo

import "strings"

type installConfig struct {
	installRoot string
	archivePath string
	mirrorURL   string
	metadata    runtimeArchiveMetadata
}

// InstallOption configures explicit runtime installation and lookup.
type InstallOption func(*installConfig)

// WithInstallRoot selects the runtime-store parent. The exact runtime is installed at
// <root>/<sdk-version>/<target>.
func WithInstallRoot(path string) InstallOption {
	return func(config *installConfig) { config.installRoot = path }
}

// WithRuntimeArchive installs from a local exact-version archive instead of downloading it.
// The archive must match the SDK's compiled SHA-256 digest.
func WithRuntimeArchive(path string) InstallOption {
	return func(config *installConfig) { config.archivePath = path }
}

// WithRuntimeMirror replaces the default GitHub release origin. Version, target, filename,
// and expected digest remain fixed by this SDK.
func WithRuntimeMirror(baseURL string) InstallOption {
	return func(config *installConfig) { config.mirrorURL = strings.TrimRight(baseURL, "/") }
}
