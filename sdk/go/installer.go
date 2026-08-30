package silo

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	maxRuntimeArchiveBytes   int64 = 512 << 20
	maxRuntimeExtractedBytes int64 = 1 << 30
)

// RuntimeTarget identifies an official Silo host runtime target.
type RuntimeTarget string

const (
	RuntimeTargetDarwinARM64   RuntimeTarget = "darwin-arm64"
	RuntimeTargetLinuxAMD64GNU RuntimeTarget = "linux-amd64-gnu"
	RuntimeTargetLinuxARM64GNU RuntimeTarget = "linux-arm64-gnu"
)

// RuntimeInstallation describes one complete exact-version runtime installation.
type RuntimeInstallation struct {
	Version string
	Target  RuntimeTarget
	Root    string
}

// InstallRuntime explicitly acquires and installs the exact runtime required by this SDK.
// It never modifies machine, image, key, log, or database state.
func InstallRuntime(ctx context.Context, opts ...InstallOption) (*RuntimeInstallation, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidArgument, "", "context must not be nil")
	}
	target, err := currentRuntimeTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	metadata := runtimeArchives[target]
	config := installConfig{metadata: metadata}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "install option must not be nil")
		}
		option(&config)
	}
	return installRuntime(ctx, target, config)
}

// InstalledRuntime returns the exact SDK runtime when it is completely installed.
// It returns nil, nil when no installation exists.
func InstalledRuntime(opts ...InstallOption) (*RuntimeInstallation, error) {
	target, err := currentRuntimeTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	config := installConfig{metadata: runtimeArchives[target]}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "install option must not be nil")
		}
		option(&config)
	}
	root, err := resolveInstallRoot(config.installRoot)
	if err != nil {
		return nil, err
	}
	finalRoot := filepath.Join(root, Version, string(target))
	valid, err := validateRuntimeInstallation(finalRoot)
	if err != nil {
		return nil, err
	}
	if !valid {
		if _, statErr := os.Lstat(finalRoot); statErr == nil {
			return nil, newError(ErrorInstallation, "", "existing runtime installation is incomplete or invalid: "+finalRoot)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, newError(ErrorInstallation, "", "inspect runtime installation: "+statErr.Error())
		}
		return nil, nil
	}
	return &RuntimeInstallation{Version: Version, Target: target, Root: finalRoot}, nil
}

func currentRuntimeTarget(goos, goarch string) (RuntimeTarget, error) {
	switch {
	case goos == "darwin" && goarch == "arm64":
		return RuntimeTargetDarwinARM64, nil
	case goos == "linux" && goarch == "amd64":
		return RuntimeTargetLinuxAMD64GNU, nil
	case goos == "linux" && goarch == "arm64":
		return RuntimeTargetLinuxARM64GNU, nil
	default:
		return "", newError(ErrorUnsupportedTarget, "", fmt.Sprintf("Silo does not support host target %s/%s", goos, goarch))
	}
}

func installRuntime(ctx context.Context, target RuntimeTarget, config installConfig) (*RuntimeInstallation, error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	metadata := config.metadata
	if metadata.version != Version || metadata.target != target || metadata.name == "" {
		return nil, newError(ErrorRuntimeReleaseUnavailable, "", "runtime archive metadata does not match this SDK")
	}
	if len(metadata.sha256) != sha256.Size*2 {
		return nil, newError(ErrorRuntimeReleaseUnavailable, "", "runtime archive digest is not available for Silo "+Version+" and "+string(target))
	}
	if _, err := hex.DecodeString(metadata.sha256); err != nil {
		return nil, newError(ErrorRuntimeReleaseUnavailable, "", "runtime archive digest is invalid: "+err.Error())
	}

	installRoot, err := resolveInstallRoot(config.installRoot)
	if err != nil {
		return nil, err
	}
	versionRoot := filepath.Join(installRoot, Version)
	if err := os.MkdirAll(versionRoot, 0o700); err != nil {
		return nil, newError(ErrorInstallation, "", "create runtime version directory: "+err.Error())
	}

	lock, err := acquireInstallLock(ctx, filepath.Join(versionRoot, "."+string(target)+".lock"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.close() }()

	finalRoot := filepath.Join(versionRoot, string(target))
	valid, err := validateRuntimeInstallation(finalRoot)
	if err != nil {
		return nil, err
	}
	if valid {
		return &RuntimeInstallation{Version: Version, Target: target, Root: finalRoot}, nil
	}
	if _, statErr := os.Lstat(finalRoot); statErr == nil {
		return nil, newError(ErrorInstallation, "", "existing runtime installation is incomplete or invalid: "+finalRoot)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, newError(ErrorInstallation, "", "inspect runtime installation: "+statErr.Error())
	}

	archive, err := materializeRuntimeArchive(ctx, versionRoot, config, metadata)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(archive) }()

	stage, err := os.MkdirTemp(versionRoot, "."+string(target)+".install-")
	if err != nil {
		return nil, newError(ErrorInstallation, "", "create runtime staging directory: "+err.Error())
	}
	stageOwned := true
	defer func() {
		if stageOwned {
			_ = os.RemoveAll(stage)
		}
	}()

	if err := extractRuntimeArchive(ctx, archive, stage, metadata); err != nil {
		return nil, err
	}
	valid, err = validateRuntimeInstallation(stage)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, newError(ErrorInstallation, "", "extracted runtime is incomplete")
	}
	if err := syncDirectory(stage); err != nil {
		return nil, newError(ErrorInstallation, "", "sync runtime staging directory: "+err.Error())
	}
	if err := os.Rename(stage, finalRoot); err != nil {
		return nil, newError(ErrorInstallation, "", "atomically install runtime: "+err.Error())
	}
	stageOwned = false
	if err := syncDirectory(versionRoot); err != nil {
		return nil, newError(ErrorInstallation, "", "sync runtime version directory: "+err.Error())
	}

	return &RuntimeInstallation{Version: Version, Target: target, Root: finalRoot}, nil
}

func resolveInstallRoot(explicit string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) {
			return "", newError(ErrorInvalidArgument, "", "install root must be absolute: "+explicit)
		}
		return filepath.Clean(explicit), nil
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome != "" {
		if !filepath.IsAbs(dataHome) {
			return "", newError(ErrorRelativeEnvironmentPath, "", "XDG_DATA_HOME must be an absolute path: "+dataHome)
		}
		return filepath.Join(filepath.Clean(dataHome), "silo", "runtimes"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", newError(ErrorDataDirUnavailable, "", "could not resolve Silo runtime installation directory from XDG_DATA_HOME or HOME")
	}
	return filepath.Join(home, ".local", "share", "silo", "runtimes"), nil
}

func materializeRuntimeArchive(ctx context.Context, parent string, config installConfig, metadata runtimeArchiveMetadata) (string, error) {
	output, err := os.CreateTemp(parent, ".runtime-archive-*.tar.zst")
	if err != nil {
		return "", newError(ErrorInstallation, "", "create temporary runtime archive: "+err.Error())
	}
	outputPath := output.Name()
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(outputPath)
		}
	}()

	hash := sha256.New()
	writer := io.MultiWriter(output, hash)
	if config.archivePath != "" {
		input, openErr := os.Open(config.archivePath)
		if openErr != nil {
			return "", newError(ErrorInstallation, "", "open local runtime archive: "+openErr.Error())
		}
		copyErr := copyArchiveWithLimit(ctx, writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", newError(ErrorInstallation, "", "close local runtime archive: "+closeErr.Error())
		}
	} else {
		origin := config.mirrorURL
		if origin == "" {
			origin = defaultRuntimeReleaseOrigin
		}
		url := origin + "/v" + metadata.version + "/" + metadata.name
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if requestErr != nil {
			return "", newError(ErrorInstallation, "", "create runtime download request: "+requestErr.Error())
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			if ctx.Err() != nil {
				return "", contextError(ctx.Err())
			}
			return "", newError(ErrorInstallation, "", "download runtime archive: "+requestErr.Error())
		}
		if response.Body == nil {
			return "", newError(ErrorInstallation, "", "runtime archive response has no body")
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return "", newError(ErrorInstallation, "", fmt.Sprintf("download runtime archive: unexpected HTTP status %s", response.Status))
		}
		if response.ContentLength > maxRuntimeArchiveBytes {
			_ = response.Body.Close()
			return "", newError(ErrorInstallation, "", "runtime archive exceeds the 512 MiB download limit")
		}
		copyErr := copyArchiveWithLimit(ctx, writer, response.Body)
		closeErr := response.Body.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", newError(ErrorInstallation, "", "close runtime archive response: "+closeErr.Error())
		}
	}

	actualDigest := hex.EncodeToString(hash.Sum(nil))
	if actualDigest != strings.ToLower(metadata.sha256) {
		return "", newError(ErrorArchiveIntegrity, "", fmt.Sprintf("runtime archive SHA-256 mismatch: expected %s, got %s", metadata.sha256, actualDigest))
	}
	if err := output.Sync(); err != nil {
		return "", newError(ErrorInstallation, "", "sync runtime archive: "+err.Error())
	}
	if err := output.Close(); err != nil {
		return "", newError(ErrorInstallation, "", "close runtime archive: "+err.Error())
	}
	keep = true
	return outputPath, nil
}

func copyArchiveWithLimit(ctx context.Context, destination io.Writer, source io.Reader) error {
	reader := &contextReader{ctx: ctx, reader: io.LimitReader(source, maxRuntimeArchiveBytes+1)}
	written, err := io.Copy(destination, reader)
	if err != nil {
		if ctx.Err() != nil {
			return contextError(ctx.Err())
		}
		return newError(ErrorInstallation, "", "read runtime archive: "+err.Error())
	}
	if written > maxRuntimeArchiveBytes {
		return newError(ErrorInstallation, "", "runtime archive exceeds the 512 MiB download limit")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

var runtimeFiles = map[string]os.FileMode{
	"bin/vmmon":               0o755,
	"bin/netd":                0o755,
	"bin/krun":                0o755,
	"assets/kernel-default":   0o644,
	"assets/initramfs":        0o644,
	"assets/agent":            0o755,
	"THIRD_PARTY_NOTICES":     0o644,
	"LICENSES/APACHE-2.0.txt": 0o644,
}

var runtimeDirectories = map[string]struct{}{
	"bin": {}, "assets": {}, "LICENSES": {},
}

func extractRuntimeArchive(ctx context.Context, archivePath, destination string, metadata runtimeArchiveMetadata) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return newError(ErrorInstallation, "", "open verified runtime archive: "+err.Error())
	}
	defer func() { _ = archive.Close() }()

	decoder, err := zstd.NewReader(archive, zstd.WithDecoderMaxMemory(1<<30), zstd.WithDecoderMaxWindow(1<<30))
	if err != nil {
		return newError(ErrorArchiveIntegrity, "", "open zstd runtime archive: "+err.Error())
	}
	defer decoder.Close()

	reader := tar.NewReader(&contextReader{ctx: ctx, reader: decoder})
	topLevel := strings.TrimSuffix(metadata.name, ".tar.zst")
	seen := make(map[string]struct{}, len(runtimeFiles)+len(runtimeDirectories))
	rootSeen := false
	var extractedBytes int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			if ctx.Err() != nil {
				return contextError(ctx.Err())
			}
			return newError(ErrorArchiveIntegrity, "", "read runtime tar archive: "+nextErr.Error())
		}
		relative, pathErr := safeArchivePath(header.Name, topLevel)
		if pathErr != nil {
			return pathErr
		}
		if relative == "" {
			if header.Typeflag != tar.TypeDir {
				return newError(ErrorArchiveIntegrity, "", "runtime archive root must be a directory")
			}
			if rootSeen {
				return newError(ErrorArchiveIntegrity, "", "runtime archive contains duplicate root directory")
			}
			rootSeen = true
			continue
		}
		if _, duplicate := seen[relative]; duplicate {
			return newError(ErrorArchiveIntegrity, "", "runtime archive contains duplicate entry: "+relative)
		}
		seen[relative] = struct{}{}

		destinationPath := filepath.Join(destination, filepath.FromSlash(relative))
		switch header.Typeflag {
		case tar.TypeDir:
			if _, expected := runtimeDirectories[relative]; !expected {
				return newError(ErrorArchiveIntegrity, "", "runtime archive contains unexpected directory: "+relative)
			}
			if err := os.Mkdir(destinationPath, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return newError(ErrorInstallation, "", "create runtime directory: "+err.Error())
			}
			if err := os.Chmod(destinationPath, 0o755); err != nil {
				return newError(ErrorInstallation, "", "set runtime directory mode: "+err.Error())
			}
		case tar.TypeReg, tar.TypeRegA:
			expectedMode, expected := runtimeFiles[relative]
			if !expected {
				return newError(ErrorArchiveIntegrity, "", "runtime archive contains unexpected file: "+relative)
			}
			if header.Size < 0 || header.Size > maxRuntimeArchiveBytes || extractedBytes > maxRuntimeExtractedBytes-header.Size {
				return newError(ErrorArchiveIntegrity, "", "runtime archive file has invalid size: "+relative)
			}
			if header.FileInfo().Mode().Perm() != expectedMode {
				return newError(ErrorArchiveIntegrity, "", fmt.Sprintf("runtime archive file %s has mode %04o, expected %04o", relative, header.FileInfo().Mode().Perm(), expectedMode))
			}
			if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
				return newError(ErrorInstallation, "", "create runtime file parent: "+err.Error())
			}
			extractedBytes += header.Size
			file, openErr := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, expectedMode)
			if openErr != nil {
				return newError(ErrorInstallation, "", "create runtime file: "+openErr.Error())
			}
			written, copyErr := io.Copy(file, &contextReader{ctx: ctx, reader: reader})
			chmodErr := file.Chmod(expectedMode)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil {
				if ctx.Err() != nil {
					return contextError(ctx.Err())
				}
				return newError(ErrorInstallation, "", "extract runtime file: "+copyErr.Error())
			}
			if written != header.Size {
				return newError(ErrorArchiveIntegrity, "", "runtime archive file was truncated: "+relative)
			}
			if chmodErr != nil {
				return newError(ErrorInstallation, "", "set runtime file mode: "+chmodErr.Error())
			}
			if syncErr != nil {
				return newError(ErrorInstallation, "", "sync runtime file: "+syncErr.Error())
			}
			if closeErr != nil {
				return newError(ErrorInstallation, "", "close runtime file: "+closeErr.Error())
			}
		default:
			return newError(ErrorArchiveIntegrity, "", fmt.Sprintf("runtime archive entry %s has forbidden type %d", relative, header.Typeflag))
		}
	}
	if !rootSeen {
		return newError(ErrorArchiveIntegrity, "", "runtime archive is missing its top-level directory")
	}
	for required := range runtimeFiles {
		if _, ok := seen[required]; !ok {
			return newError(ErrorArchiveIntegrity, "", "runtime archive is missing required file: "+required)
		}
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		return newError(ErrorInstallation, "", "set runtime root mode: "+err.Error())
	}
	for directory := range runtimeDirectories {
		if err := os.Chmod(filepath.Join(destination, filepath.FromSlash(directory)), 0o755); err != nil {
			return newError(ErrorInstallation, "", "set runtime directory mode: "+err.Error())
		}
	}
	return nil
}

func safeArchivePath(name, expectedRoot string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", newError(ErrorArchiveIntegrity, "", "runtime archive contains an unsafe path: "+name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", newError(ErrorArchiveIntegrity, "", "runtime archive contains an unsafe path: "+name)
	}
	if clean != name && clean+"/" != name {
		return "", newError(ErrorArchiveIntegrity, "", "runtime archive contains a non-canonical path: "+name)
	}
	if clean == expectedRoot {
		return "", nil
	}
	prefix := expectedRoot + "/"
	if !strings.HasPrefix(clean, prefix) {
		return "", newError(ErrorArchiveIntegrity, "", "runtime archive contains an unexpected top-level path: "+name)
	}
	relative := strings.TrimPrefix(clean, prefix)
	if relative == "" || relative == "." || strings.HasPrefix(relative, "../") {
		return "", newError(ErrorArchiveIntegrity, "", "runtime archive contains an unsafe path: "+name)
	}
	return relative, nil
}

func validateRuntimeInstallation(root string) (bool, error) {
	rootInfo, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, newError(ErrorInstallation, "", "inspect runtime root: "+err.Error())
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o755 {
		return false, nil
	}
	walkErr := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		relative, relativeErr := filepath.Rel(root, current)
		if relativeErr != nil {
			return relativeErr
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if _, expected := runtimeDirectories[relative]; !expected {
				return fmt.Errorf("unexpected runtime directory %s", relative)
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("runtime directory %s has mode %04o", relative, info.Mode().Perm())
			}
			return nil
		}
		if _, expected := runtimeFiles[relative]; !expected {
			return fmt.Errorf("unexpected runtime file %s", relative)
		}
		return nil
	})
	if walkErr != nil {
		return false, nil
	}
	for relative, expectedMode := range runtimeFiles {
		info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if errors.Is(statErr, os.ErrNotExist) {
			return false, nil
		}
		if statErr != nil {
			return false, newError(ErrorInstallation, "", "inspect runtime file: "+statErr.Error())
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != expectedMode {
			return false, nil
		}
	}
	return true, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
