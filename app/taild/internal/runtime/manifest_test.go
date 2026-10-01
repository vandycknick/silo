package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	silo "github.com/vandycknick/silo/sdk/go"
)

// These are manifest-format unit fixtures, not claims about runtime components.
func manifestFixture(t *testing.T) (string, Manifest) {
	t.Helper()
	root := t.TempDir()
	data := []byte("manifest unit fixture bytes")
	if err := os.WriteFile(filepath.Join(root, "fixture"), data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	target, _ := hostTarget()
	m := Manifest{Version: silo.Version, Target: target, Files: map[string]string{"fixture": hex.EncodeToString(hash[:])}}
	writeManifest(t, root, m)
	return root, m
}
func writeManifest(t *testing.T, root string, m Manifest) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "runtime-manifest.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestManifestValidatesActualFiles(t *testing.T) {
	root, _ := manifestFixture(t)
	got, err := ValidateManifest(root)
	if err != nil || got.Version != silo.Version {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(filepath.Join(root, "fixture"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateManifest(root); err == nil {
		t.Fatal("hash mismatch accepted")
	}
}
func TestManifestRejectsInvalidRootsAndMetadata(t *testing.T) {
	for _, name := range []string{"version", "target", "escape", "absolute", "missing-file", "unlisted-file", "symlink", "parent-symlink", "missing-manifest", "manifest-symlink", "invalid-json", "extra-json"} {
		t.Run(name, func(t *testing.T) {
			root, m := manifestFixture(t)
			switch name {
			case "version":
				m.Version = "not-sdk-version"
			case "target":
				m.Target = "wrong-target"
			case "escape":
				m.Files["../outside"] = m.Files["fixture"]
			case "absolute":
				m.Files["/outside"] = m.Files["fixture"]
			case "missing-file":
				m.Files["missing"] = m.Files["fixture"]
			case "unlisted-file":
				if err := os.WriteFile(filepath.Join(root, "unlisted"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(root, "fixture"), filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
				m.Files["link"] = m.Files["fixture"]
			case "parent-symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "dir")); err != nil {
					t.Fatal(err)
				}
				m.Files["dir/escape"] = m.Files["fixture"]
			}
			writeManifest(t, root, m)
			p := filepath.Join(root, "runtime-manifest.json")
			switch name {
			case "missing-manifest":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			case "manifest-symlink":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "fixture"), p); err != nil {
					t.Fatal(err)
				}
			case "invalid-json":
				if err := os.WriteFile(p, []byte("not-json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-json":
				f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("{}")
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ValidateManifest(root); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	root, _ := manifestFixture(t)
	link := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateManifest(link); err == nil {
		t.Fatal("symlink runtime root accepted")
	}
}
