package testfixture

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestForwardGuestFileValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing map[string]byte
		files    []GuestFile
	}{
		{"absolute", nil, []GuestFile{{Path: "/bin/probe"}}},
		{"traversal", nil, []GuestFile{{Path: "../probe"}}},
		{"embedded-traversal", nil, []GuestFile{{Path: "bin/../probe"}}},
		{"empty", nil, []GuestFile{{}}},
		{"backslash", nil, []GuestFile{{Path: `bin\probe`}}},
		{"duplicate-rootfs", map[string]byte{"bin/probe": tar.TypeReg}, []GuestFile{{Path: "bin/probe"}}},
		{"duplicate-extra", nil, []GuestFile{{Path: "probe"}, {Path: "probe"}}},
		{"symlink-parent", map[string]byte{"bin": tar.TypeSymlink}, []GuestFile{{Path: "bin/probe"}}},
		{"regular-parent", nil, []GuestFile{{Path: "bin/probe"}, {Path: "bin"}}},
		{"unsafe-mode", nil, []GuestFile{{Path: "probe", Mode: 04755}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			if err := appendGuestFiles(tar.NewWriter(&archive), tc.existing, tc.files); err == nil {
				t.Fatal("unsafe input accepted")
			}
			if archive.Len() != 0 {
				t.Fatal("invalid set partially written")
			}
		})
	}
}

func TestForwardGuestFileArchive(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	data := []byte("real guest executable")
	if err := appendGuestFiles(tw, map[string]byte{"usr": tar.TypeDir}, []GuestFile{{Path: "usr/local/bin/probe", Mode: 0755, Data: data}}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&archive)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(tr)
	if err != nil || h.Name != "usr/local/bin/probe" || h.Mode != 0755 || h.Typeflag != tar.TypeReg || !bytes.Equal(got, data) {
		t.Fatalf("incorrect archive entry: %+v %q %v", h, got, err)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatal(err)
	}
}

func TestRegistryImageCacheKeysIncludeRootfsAndSortedGuestFiles(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "base"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	files := []GuestFile{{Path: "z", Mode: 0644, Data: []byte("last")}, {Path: "a", Mode: 0755, Data: []byte("first")}}
	first := cachedRegistryImage(t, rootfs, files)
	reordered := cachedRegistryImage(t, rootfs, []GuestFile{files[1], files[0]})
	if &first.archive[0] != &reordered.archive[0] || &first.layer[0] != &reordered.layer[0] || &first.config[0] != &reordered.config[0] || &first.manifest[0] != &reordered.manifest[0] {
		t.Fatal("equivalent files did not reuse the cached image")
	}
	if files[0].Path != "z" {
		t.Fatal("cache sorting changed the caller's files")
	}
	for _, changed := range [][]GuestFile{
		{{Path: "z", Mode: 0600, Data: []byte("last")}, files[1]},
		{{Path: "z", Mode: 0644, Data: []byte("changed")}, files[1]},
		{{Path: "other", Mode: 0644, Data: []byte("last")}, files[1]},
	} {
		image := cachedRegistryImage(t, rootfs, changed)
		if bytes.Equal(first.manifest, image.manifest) {
			t.Fatal("changed guest file reused the original image")
		}
	}
	other := cachedRegistryImage(t, t.TempDir(), files)
	if bytes.Equal(first.manifest, other.manifest) {
		t.Fatal("different rootfs reused the original image")
	}
}
