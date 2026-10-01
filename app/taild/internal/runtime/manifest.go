package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/config"
	silo "github.com/vandycknick/silo/sdk/go"
)

type Manifest struct {
	Version string            `json:"version"`
	Target  string            `json:"target"`
	Files   map[string]string `json:"files"`
}

var ErrMissingRuntime = errors.New("runtime is missing; install it explicitly before starting taild")

func Root(c config.Config) (string, error) {
	if c.RuntimeRoot != "" {
		return c.RuntimeRoot, nil
	}
	installed, err := silo.InstalledRuntime(silo.WithInstallRoot(c.RuntimeStore()))
	if err != nil {
		return "", errors.New("installed runtime is invalid")
	}
	if installed == nil {
		return "", ErrMissingRuntime
	}
	return installed.Root, nil
}

// ValidateManifest verifies actual installed bytes, not the installer's expected
// version field. Every regular file except the manifest must be listed.
func ValidateManifest(root string) (Manifest, error) {
	var m Manifest
	fail := func() (Manifest, error) {
		return Manifest{}, errors.New("runtime manifest missing, invalid, or incompatible")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail()
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return fail()
	}
	defer r.Close()
	info, err = r.Lstat("runtime-manifest.json")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return fail()
	}
	f, err := r.Open("runtime-manifest.json")
	if err != nil {
		return fail()
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	err = d.Decode(&m)
	var extra any
	end := d.Decode(&extra)
	_ = f.Close()
	if err != nil || end != io.EOF || m.Version != silo.Version || len(m.Files) == 0 {
		return fail()
	}
	key, triple := hostTarget()
	if key == "" || m.Target != key && m.Target != triple {
		return fail()
	}
	for name, digest := range m.Files {
		if !fs.ValidPath(name) || path.Clean(name) != name || strings.Contains(name, "\\") || name == "runtime-manifest.json" || len(digest) != 64 {
			return fail()
		}
		if _, err = hex.DecodeString(digest); err != nil {
			return fail()
		}
	}
	seen := 0
	err = filepath.WalkDir(root, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if entry.IsDir() {
			return nil
		}
		name, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if name == "runtime-manifest.json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("nonregular runtime file")
		}
		want, ok := m.Files[name]
		if !ok {
			return errors.New("unlisted runtime file")
		}
		f, err := r.Open(name)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		ce := f.Close()
		if err != nil || ce != nil || hex.EncodeToString(h.Sum(nil)) != want {
			return errors.New("runtime hash mismatch")
		}
		seen++
		return nil
	})
	if err != nil || seen != len(m.Files) {
		return fail()
	}
	return m, nil
}

func hostTarget() (string, string) {
	switch goruntime.GOOS + "/" + goruntime.GOARCH {
	case "linux/amd64":
		return "linux-amd64-gnu", "x86_64-unknown-linux-gnu"
	case "linux/arm64":
		return "linux-arm64-gnu", "aarch64-unknown-linux-gnu"
	case "darwin/arm64":
		return "darwin-arm64", "aarch64-apple-darwin"
	default:
		return "", ""
	}
}
