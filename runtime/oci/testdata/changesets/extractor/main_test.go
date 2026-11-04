//go:build linux

package main

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestComparatorNegativeControls(t *testing.T) {
	original := []Row{{Path: b64([]byte("raw-\xff")), Kind: "regular", Mode: 0755, Xattrs: []Attribute{}, MtimeSeconds: 1, MtimeNanos: 123456789, Length: new(uint64(3)), Content: new(sha([]byte("old"))), Group: new(b64([]byte("raw-\xff"))), Links: new(uint32(1))}}
	controls := map[string]func([]Row) []Row{
		"wrong-opaque-survival": func(rows []Row) []Row { return nil },
		"wrong-hardlink-group":  func(rows []Row) []Row { rows[0].Group = new(b64([]byte("wrong"))); return rows },
		"wrong-nanoseconds":     func(rows []Row) []Row { rows[0].MtimeNanos++; return rows },
		"wrong-raw-name":        func(rows []Row) []Row { rows[0].Path = b64([]byte("raw-\xfe")); return rows },
		"duplicate-raw-name":    func(rows []Row) []Row { return append(rows, rows[0]) },
		"invalid-raw-encoding":  func(rows []Row) []Row { rows[0].Path = "YR"; return rows },
	}
	if got := differences(original, original); len(got) != 0 {
		t.Fatalf("equal listing differs: %#v", got)
	}
	for name, control := range controls {
		t.Run(name, func(t *testing.T) {
			wrong := append([]Row(nil), original...)
			if len(differences(original, control(wrong))) == 0 {
				t.Fatal("corruption control escaped comparator")
			}
		})
	}
}

func TestCollectorRealRawNamesAndHardlinkedSymlinkAndFifo(t *testing.T) {
	root := t.TempDir()
	raw := filepath.Join(root, "raw-\xff")
	if err := os.WriteFile(raw, []byte("body"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(raw, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-\xfe", filepath.Join(root, "s")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "s"), filepath.Join(root, "t")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	rows, problems := collect(root)
	if len(problems) != 0 {
		t.Fatalf("collection failed, not an equality result: %v", problems)
	}
	byName := make(map[string]Row)
	for _, row := range rows {
		byName[row.Path] = row
	}
	file := byName[b64([]byte("raw-\xff"))]
	if file.Content == nil || *file.Content != sha([]byte("body")) || file.Links == nil || *file.Links != 2 || file.Group == nil || *file.Group != b64([]byte("alias")) {
		t.Fatalf("wrong file evidence: %#v", file)
	}
	s := byName[b64([]byte("s"))]
	alias := byName[b64([]byte("t"))]
	if s.Kind != "symlink" || s.Target == nil || *s.Target != b64([]byte("missing-\xfe")) || !reflect.DeepEqual(s.Group, alias.Group) || s.Links == nil || *s.Links != 2 {
		t.Fatalf("wrong symlink inode evidence: %#v %#v", s, alias)
	}
	fifo := byName[b64([]byte("fifo"))]
	if fifo.Kind != "fifo" || fifo.Content != nil || fifo.Length != nil {
		t.Fatalf("special-file body was read: %#v", fifo)
	}
	if _, ok := byName[""]; !ok {
		t.Fatal("root metadata omitted")
	}
}

func writeClassificationArchive(t *testing.T, path string, header *tar.Header, body []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(header); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingCapabilityWithoutErrorIsSemantic(t *testing.T) {
	base := t.TempDir()
	writeClassificationArchive(t, filepath.Join(base, "regular.tar"), &tar.Header{
		Name: "file", Typeflag: tar.TypeReg, Size: 4, Mode: 0644,
		Uid: os.Getuid(), Gid: os.Getgid(), ModTime: time.Unix(1, 0),
	}, []byte("body"))
	// Deliberately wrong expected metadata is a comparator negative control:
	// extraction really succeeds, but the expected capability is absent.
	capability := []byte{1, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	expected := []Row{{
		Path: b64([]byte("file")), Kind: "regular", Mode: 0644,
		UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), MtimeSeconds: 1,
		Xattrs: []Attribute{{Name: b64([]byte("security.capability")), Value: b64(capability)}},
		Length: new(uint64(4)), Content: new(sha([]byte("body"))),
		Group: new(b64([]byte("file"))), Links: new(uint32(1)),
	}}
	result := applyCase(context.Background(), base, t.TempDir(), Case{
		Name: "missing-capability-without-error", Layers: []Layer{{Tar: "regular.tar"}}, Expected: expected,
	})
	if result.Status != "semantic-difference" || result.Error != "" || len(result.CollectionErrors) != 0 {
		t.Fatalf("missing capability is not evidence of namespace denial: %#v", result)
	}
	found := false
	for _, diff := range result.Differences {
		if diff.Path == b64([]byte("file")) && diff.Field == "xattrs" {
			found = true
		}
	}
	if !found {
		t.Fatalf("complete missing-attribute difference was lost: %#v", result.Differences)
	}
	// Exercise the noninitial-userns default-skip classifier even when this
	// unit test itself runs in the initial namespace. This is a pure unit
	// input, not a mocked extractor or permission failure.
	if omitted := defaultUserNamespaceDeviceOmissions(expected, result.Actual); len(omitted) != 0 {
		t.Fatalf("namespace flag alone invented an attribute limitation: %v", omitted)
	}
}

func TestActualIgnoredSymlinkAttributeIsSemantic(t *testing.T) {
	base := t.TempDir()
	// The pinned default applier actually ignores this symlink attribute and
	// returns success. Its missing attribute is a semantic difference, not
	// proof that an extraction error propagated to the caller.
	writeClassificationArchive(t, filepath.Join(base, "denied.tar"), &tar.Header{
		Name: "denied", Typeflag: tar.TypeSymlink, Linkname: "missing", Mode: 0777,
		Uid: os.Getuid(), Gid: os.Getgid(), ModTime: time.Unix(1, 0),
		Xattrs: map[string]string{"user.silo-denial": "value"},
	}, nil)
	result := applyCase(context.Background(), base, t.TempDir(), Case{
		Name: "actual-ignored-symlink-xattr", Layers: []Layer{{Tar: "denied.tar"}},
		Expected: []Row{{
			Path: b64([]byte("denied")), Kind: "symlink", Mode: 0777,
			UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), MtimeSeconds: 1,
			Xattrs: []Attribute{{Name: b64([]byte("user.silo-denial")), Value: b64([]byte("value"))}},
			Target: new(b64([]byte("missing"))), Group: new(b64([]byte("denied"))), Links: new(uint32(1)),
		}},
	})
	if result.Status != "semantic-difference" || result.Error != "" || len(result.CollectionErrors) != 0 {
		t.Fatalf("successful omission was mislabeled as a propagated environment failure: %#v", result)
	}
	if len(result.Actual) == 0 || len(result.Differences) == 0 {
		t.Fatalf("partial extraction/listing differences were discarded: %#v", result)
	}
}

func TestActualPermissionDenialClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	// Linux forbids user.* attributes on symlinks. Exercise the real syscall
	// directly to test error classification, without pretending that the
	// containerd default applier propagates the same error.
	err := unix.Lsetxattr(path, "user.silo-denial", []byte("value"), 0)
	if err == nil {
		_ = unix.Lremovexattr(path, "user.silo-denial")
		t.Fatal("Linux symlink unexpectedly accepted a user xattr")
	}
	if !unavailable(err) {
		t.Fatalf("actual permission/unsupported error was not classified unavailable: %v", err)
	}
}

func TestUserNamespaceDefaultSkipIsOnlyAbsentDevices(t *testing.T) {
	expected := []Row{
		{Path: b64([]byte("dev/character")), Kind: "character-device"},
		{Path: b64([]byte("dev/block")), Kind: "block-device"},
		{Path: b64([]byte("file")), Kind: "regular", Xattrs: []Attribute{{
			Name: b64([]byte("trusted.example")), Value: b64([]byte("value")),
		}}},
	}
	actual := []Row{
		// A wrong object kind is a semantic difference, not a skipped device.
		{Path: b64([]byte("dev/block")), Kind: "regular"},
		{Path: b64([]byte("file")), Kind: "regular"},
	}
	want := []string{
		"device absent in noninitial user namespace (containerd default skips device creation): " + b64([]byte("dev/character")),
	}
	if got := defaultUserNamespaceDeviceOmissions(expected, actual); !reflect.DeepEqual(got, want) {
		t.Fatalf("default namespace skip attribution erased a semantic difference: got %v, want %v", got, want)
	}
}
