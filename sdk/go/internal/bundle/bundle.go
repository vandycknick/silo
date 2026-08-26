// Package bundle locates or materializes the private platform FFI bridge.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const sdkVersion = "0.1.0"

// Path returns an absolute path to the exact native bridge for this SDK.
func Path() (string, error) {
	if override := os.Getenv("SILO_GO_FFI_PATH"); override != "" {
		return validateOverride(override)
	}
	if !platformSupported {
		return "", fmt.Errorf("Silo Go SDK does not support this host target")
	}
	if len(embeddedLibrary) == 0 || embeddedDigest == "" {
		return "", fmt.Errorf("embedded Silo Go bridge is unavailable in this development source; set SILO_GO_FFI_PATH")
	}
	root, err := cacheRoot()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, "silo", "go-ffi", sdkVersion, platformTarget)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create Silo bridge cache: %w", err)
	}
	destination := filepath.Join(directory, platformFilename)
	if validDigest(destination, embeddedDigest) {
		return destination, nil
	}
	temporary, err := os.CreateTemp(directory, ".bridge-*")
	if err != nil {
		return "", fmt.Errorf("create temporary Silo bridge: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o700); err != nil {
		return "", fmt.Errorf("set Silo bridge mode: %w", err)
	}
	if _, err := temporary.Write(embeddedLibrary); err != nil {
		return "", fmt.Errorf("write Silo bridge: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync Silo bridge: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close Silo bridge: %w", err)
	}
	if !validDigest(temporaryPath, embeddedDigest) {
		return "", errors.New("embedded Silo bridge digest does not match release metadata")
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		if !validDigest(destination, embeddedDigest) {
			return "", fmt.Errorf("install Silo bridge: %w", err)
		}
		_ = os.Remove(temporaryPath)
	}
	keep = true
	return destination, nil
}

func validateOverride(value string) (string, error) {
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("SILO_GO_FFI_PATH must be absolute: %s", value)
	}
	path, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", fmt.Errorf("resolve SILO_GO_FFI_PATH: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect SILO_GO_FFI_PATH: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("SILO_GO_FFI_PATH is not a regular file: %s", path)
	}
	return path, nil
}

func cacheRoot() (string, error) {
	if value := os.Getenv("XDG_CACHE_HOME"); value != "" {
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("XDG_CACHE_HOME must be absolute: %s", value)
		}
		return filepath.Clean(value), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", errors.New("could not resolve Silo bridge cache from XDG_CACHE_HOME or HOME")
	}
	return filepath.Join(home, ".cache"), nil
}

func validDigest(path, expected string) bool {
	contents, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]) == expected
}
