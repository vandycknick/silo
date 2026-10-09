package testfixture

import (
	"archive/tar"
	"bytes"
	"io"
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
