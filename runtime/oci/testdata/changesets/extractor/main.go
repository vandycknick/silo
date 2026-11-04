//go:build linux

// Test-only independent filesystem evidence. No daemon, snapshotter or VM.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive"
	"golang.org/x/sys/unix"
)

const extractorVersion = "github.com/containerd/containerd/v2@v2.4.2"

type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Row struct {
	Path         string      `json:"path"`
	Kind         string      `json:"kind"`
	Mode         uint32      `json:"mode"`
	UID          uint32      `json:"uid"`
	GID          uint32      `json:"gid"`
	MtimeSeconds int64       `json:"mtimeSeconds"`
	MtimeNanos   uint32      `json:"mtimeNanos"`
	Xattrs       []Attribute `json:"xattrs"`
	Length       *uint64     `json:"length"`
	Content      *string     `json:"content"`
	Target       *string     `json:"target"`
	DeviceMajor  *uint32     `json:"deviceMajor"`
	DeviceMinor  *uint32     `json:"deviceMinor"`
	Group        *string     `json:"group"`
	Links        *uint32     `json:"links"`
}

type Layer struct {
	Tar        string `json:"tar"`
	Blob       string `json:"blob,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Size       int64  `json:"size,omitempty"`
	MediaType  string `json:"mediaType,omitempty"`
	DiffID     string `json:"diffId,omitempty"`
	PackLength uint64 `json:"packLength"`
	PackStream string `json:"packStream,omitempty"`
	Recipe     string `json:"recipe,omitempty"`
	IndexRoot  string `json:"indexRoot,omitempty"`
	Result     string `json:"result,omitempty"`
}

type LayerArtifact struct {
	DiffID     string `json:"diffId"`
	PackLength uint64 `json:"packLength"`
	PackStream string `json:"packStream"`
	Recipe     string `json:"recipe"`
	IndexRoot  string `json:"indexRoot"`
	Result     string `json:"result"`
	Directory  string `json:"directory,omitempty"`
}

type Case struct {
	Name              string          `json:"name"`
	Matrix            []string        `json:"matrix,omitempty"`
	Layers            []Layer         `json:"layers"`
	Expected          []Row           `json:"expected"`
	ExpectedRejected  bool            `json:"expectedRejected"`
	SiloRejection     *string         `json:"siloRejection,omitempty"`
	SiloRejectionKind string          `json:"siloRejectionKind,omitempty"`
	Provenance        *Pin            `json:"provenance,omitempty"`
	Artifacts         []LayerArtifact `json:"artifacts,omitempty"`
	ProducerOriginal  []Row           `json:"producerOriginal,omitempty"`
	Producer          string          `json:"producer,omitempty"`
	ProducerEvidence  string          `json:"producerEvidence,omitempty"`
}

type Request struct {
	Schema int    `json:"schema"`
	Cases  []Case `json:"cases"`
}

type Difference struct {
	Path     string `json:"path"`
	Field    string `json:"field"`
	Expected any    `json:"expected"`
	Actual   any    `json:"actual"`
}

type Result struct {
	Name                 string          `json:"name"`
	Status               string          `json:"status"`
	Error                string          `json:"error,omitempty"`
	SiloRejection        *string         `json:"siloRejection,omitempty"`
	SiloRejectionKind    string          `json:"siloRejectionKind,omitempty"`
	Expected             []Row           `json:"expected"`
	Actual               []Row           `json:"actual"`
	Differences          []Difference    `json:"differences"`
	CollectionErrors     []string        `json:"collectionErrors"`
	Layers               []Layer         `json:"layers"`
	Provenance           *Pin            `json:"provenance,omitempty"`
	Artifacts            []LayerArtifact `json:"artifacts,omitempty"`
	ProducerOriginal     []Row           `json:"producerOriginal,omitempty"`
	Producer             string          `json:"producer,omitempty"`
	ProducerEvidence     string          `json:"producerEvidence,omitempty"`
	ProducerToSilo       []Difference    `json:"producerToSilo,omitempty"`
	ProducerToContainerd []Difference    `json:"producerToContainerd,omitempty"`
}

type Report struct {
	Schema      int            `json:"schema"`
	Extractor   string         `json:"extractor"`
	Options     []string       `json:"options"`
	Environment map[string]any `json:"environment"`
	Request     string         `json:"request"`
	Results     []Result       `json:"results"`
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func sha(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return fmt.Errorf("JSON request is not a regular file within the 256 MiB evidence bound")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 256<<20))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected JSON suffix: %v", err)
	}
	return nil
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// Llistxattr/Lgetxattr preserve raw names/values, and never follow symlinks.
// Retry ERANGE because even isolated roots can have LSM-generated attributes.
func xattrs(path string) ([]Attribute, error) {
	for range 4 {
		size, err := unix.Llistxattr(path, nil)
		if err != nil {
			return nil, err
		}
		if size > 1<<20 {
			return nil, fmt.Errorf("xattr name list exceeds evidence bound")
		}
		names := make([]byte, size)
		size, err = unix.Llistxattr(path, names)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result := make([]Attribute, 0)
		retry := false
		ordered := strings.Split(string(names[:size]), "\x00")
		sort.Strings(ordered)
		for _, name := range ordered {
			if name == "" {
				continue
			}
			size, err := unix.Lgetxattr(path, name, nil)
			if err != nil {
				return nil, err
			}
			if size > 16<<20 {
				return nil, fmt.Errorf("xattr value exceeds evidence bound")
			}
			value := make([]byte, size)
			size, err = unix.Lgetxattr(path, name, value)
			if errors.Is(err, unix.ERANGE) {
				retry = true
				break
			}
			if err != nil {
				return nil, err
			}
			result = append(result, Attribute{Name: b64([]byte(name)), Value: b64(value[:size])})
		}
		if retry {
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("xattrs changed repeatedly")
}

type inodeKey struct {
	device uint64
	inode  uint64
}

func collect(root string) ([]Row, []string) {
	rows := make([]Row, 0)
	problems := make([]string, 0)
	rawPaths := make(map[string]string)
	groups := make(map[inodeKey][]int)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			relative = ""
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			problems = append(problems, fmt.Sprintf("lstat %s: %v", b64([]byte(relative)), err))
			return nil
		}
		row := Row{Path: b64([]byte(relative)), Mode: stat.Mode & 07777, UID: stat.Uid, GID: stat.Gid, MtimeSeconds: stat.Mtim.Sec, MtimeNanos: uint32(stat.Mtim.Nsec), Xattrs: make([]Attribute, 0)}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			row.Kind = "directory"
		case unix.S_IFREG:
			row.Kind = "regular"
			row.Length = new(uint64(stat.Size))
			// O_NOFOLLOW protects the collector boundary even if invoked on a
			// root modified by another process. FIFOs/devices are never opened.
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				problems = append(problems, fmt.Sprintf("open %s: %v", row.Path, err))
				break
			}
			file := os.NewFile(uintptr(fd), path)
			digest := sha256.New()
			_, copyErr := io.Copy(digest, file)
			closeErr := file.Close()
			if copyErr != nil {
				problems = append(problems, copyErr.Error())
			} else {
				row.Content = new("sha256:" + hex.EncodeToString(digest.Sum(nil)))
			}
			if closeErr != nil {
				problems = append(problems, closeErr.Error())
			}
		case unix.S_IFLNK:
			row.Kind = "symlink"
			target, err := os.Readlink(path)
			if err != nil {
				problems = append(problems, err.Error())
			} else {
				row.Target = new(b64([]byte(target)))
			}
		case unix.S_IFCHR:
			row.Kind = "character-device"
			row.DeviceMajor = new(unix.Major(uint64(stat.Rdev)))
			row.DeviceMinor = new(unix.Minor(uint64(stat.Rdev)))
		case unix.S_IFBLK:
			row.Kind = "block-device"
			row.DeviceMajor = new(unix.Major(uint64(stat.Rdev)))
			row.DeviceMinor = new(unix.Minor(uint64(stat.Rdev)))
		case unix.S_IFIFO:
			row.Kind = "fifo"
		case unix.S_IFSOCK:
			row.Kind = "socket"
		default:
			row.Kind = fmt.Sprintf("unknown-%o", stat.Mode&unix.S_IFMT)
		}
		attrs, err := xattrs(path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("xattrs %s: %v", row.Path, err))
		} else {
			row.Xattrs = attrs
		}
		if row.Kind != "directory" {
			key := inodeKey{uint64(stat.Dev), stat.Ino}
			groups[key] = append(groups[key], len(rows))
		}
		rawPaths[row.Path] = relative
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		problems = append(problems, err.Error())
	}
	for _, members := range groups {
		first := members[0]
		for _, member := range members[1:] {
			if rawPaths[rows[member].Path] < rawPaths[rows[first].Path] {
				first = member
			}
		}
		group := rows[first].Path
		links := uint32(len(members))
		for _, member := range members {
			rows[member].Group = new(group)
			rows[member].Links = new(links)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rawPaths[rows[i].Path] < rawPaths[rows[j].Path] })
	return rows, problems
}

func differences(expected, actual []Row) []Difference {
	byPath := make(map[string][2]*Row)
	result := make([]Difference, 0)
	for index := range expected {
		pair := byPath[expected[index].Path]
		if pair[0] != nil {
			result = append(result, Difference{Path: expected[index].Path, Field: "duplicate-expected-entry", Expected: pair[0], Actual: &expected[index]})
		}
		pair[0] = &expected[index]
		byPath[expected[index].Path] = pair
	}
	for index := range actual {
		pair := byPath[actual[index].Path]
		if pair[1] != nil {
			result = append(result, Difference{Path: actual[index].Path, Field: "duplicate-actual-entry", Expected: pair[1], Actual: &actual[index]})
		}
		pair[1] = &actual[index]
		byPath[actual[index].Path] = pair
	}
	paths := make([]string, 0, len(byPath))
	rawPaths := make(map[string]string, len(byPath))
	encoding := base64.RawURLEncoding.Strict()
	for path := range byPath {
		paths = append(paths, path)
		raw, err := encoding.DecodeString(path)
		if err != nil || strings.ContainsAny(path, "\r\n") {
			result = append(result, Difference{Path: path, Field: "invalid-raw-path-encoding", Expected: "canonical unpadded base64url", Actual: path})
		}
		rawPaths[path] = string(raw)
	}
	sort.Slice(paths, func(i, j int) bool { return rawPaths[paths[i]] < rawPaths[paths[j]] })
	for _, path := range paths {
		pair := byPath[path]
		if pair[0] == nil || pair[1] == nil {
			result = append(result, Difference{Path: path, Field: "entry", Expected: pair[0], Actual: pair[1]})
			continue
		}
		left := reflect.ValueOf(*pair[0])
		right := reflect.ValueOf(*pair[1])
		typ := left.Type()
		for field := range left.NumField() {
			if !reflect.DeepEqual(left.Field(field).Interface(), right.Field(field).Interface()) {
				result = append(result, Difference{Path: path, Field: strings.Split(typ.Field(field).Tag.Get("json"), ",")[0], Expected: left.Field(field).Interface(), Actual: right.Field(field).Interface()})
			}
		}
	}
	return result
}

func environment(root string) map[string]any {
	values := map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "architecture": runtime.GOARCH, "uid": os.Getuid(), "gid": os.Getgid(), "collectedAt": time.Now().UTC().Format(time.RFC3339Nano), "root": root}
	if info, ok := debug.ReadBuildInfo(); ok {
		values["buildInfo"] = info.String()
	}
	if executable, err := os.Executable(); err == nil {
		if digest, err := fileDigest(executable); err == nil {
			values["helperDigest"] = digest
		}
	}
	for _, name := range []string{"uid_map", "gid_map", "status", "mountinfo"} {
		content, err := os.ReadFile("/proc/self/" + name)
		if err != nil {
			values[name] = err.Error()
		} else {
			values[name] = string(content)
		}
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(root, &stat); err != nil {
		values["statfsError"] = err.Error()
	} else {
		values["filesystemType"] = fmt.Sprintf("0x%x", stat.Type)
		values["filesystemBlockSize"] = stat.Bsize
	}
	var name unix.Utsname
	if err := unix.Uname(&name); err == nil {
		values["kernel"] = strings.TrimRight(string(name.Release[:]), "\x00")
	}
	return values
}

func unavailable(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOVERFLOW) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.ENAMETOOLONG) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func namespaceOmissions(expected, actual []Row) []string {
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(mapping))
	if len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295" {
		return nil
	}
	// Only a source-backed default skip is an environment limitation without
	// an actual syscall error. Missing security/trusted attributes alone may
	// instead be real extraction semantics (for example chown clearing caps).
	return defaultUserNamespaceDeviceOmissions(expected, actual)
}

func defaultUserNamespaceDeviceOmissions(expected, actual []Row) []string {
	devices := make(map[string]struct{})
	for _, row := range expected {
		if row.Kind == "character-device" || row.Kind == "block-device" {
			devices[row.Path] = struct{}{}
		}
	}
	if len(devices) == 0 {
		return nil
	}
	for _, row := range actual {
		delete(devices, row.Path)
	}
	missing := make([]string, 0, len(devices))
	for _, row := range expected {
		if _, absent := devices[row.Path]; absent {
			missing = append(missing, "device absent in noninitial user namespace (containerd default skips device creation): "+row.Path)
		}
	}
	return missing
}

func applyCase(ctx context.Context, base, temp string, item Case) (result Result) {
	result = Result{Name: item.Name, Expected: item.Expected, Actual: make([]Row, 0), Differences: make([]Difference, 0), CollectionErrors: make([]string, 0), Layers: item.Layers, SiloRejection: item.SiloRejection, SiloRejectionKind: item.SiloRejectionKind, Provenance: item.Provenance, Artifacts: item.Artifacts, ProducerOriginal: item.ProducerOriginal, Producer: item.Producer, ProducerEvidence: item.ProducerEvidence}
	root, err := os.MkdirTemp(temp, "merged-")
	if err != nil {
		result.Status = "environment-unavailable"
		result.Error = err.Error()
		return result
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			result.Status = "environment-unavailable"
			result.CollectionErrors = append(result.CollectionErrors, "cleanup: "+err.Error())
		}
	}()
	for _, layer := range item.Layers {
		path := layer.Tar
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			err = openErr
			break
		}
		// EXACT DEFAULTS: no filter, converter, WithParents, WithNoSameOwner,
		// platform or other opt. Version/options are retained in every report.
		_, applyErr := archive.Apply(ctx, root, file)
		closeErr := file.Close()
		if applyErr != nil {
			err = applyErr
			break
		}
		if closeErr != nil {
			err = closeErr
			break
		}
	}
	result.Actual, result.CollectionErrors = collect(root)
	result.Differences = differences(result.Expected, result.Actual)
	result.CollectionErrors = append(result.CollectionErrors, namespaceOmissions(result.Expected, result.Actual)...)
	if len(item.ProducerOriginal) != 0 {
		result.ProducerToContainerd = differences(item.ProducerOriginal, result.Actual)
		if item.SiloRejection == nil {
			result.ProducerToSilo = differences(item.ProducerOriginal, result.Expected)
		}
	}
	if err != nil {
		result.Status = "extraction-rejected"
		if unavailable(err) {
			result.Status = "environment-unavailable"
		}
		result.Error = err.Error()
		return result
	}
	if len(result.CollectionErrors) != 0 {
		result.Status = "environment-unavailable"
		return result
	}
	if item.ExpectedRejected {
		result.Status = "semantic-difference"
		result.Error = "Silo oracle rejects this namespace; containerd accepted"
		return result
	}
	if item.SiloRejection != nil {
		result.Status = "semantic-difference"
		result.Error = "Silo rejected the acquired image (" + item.SiloRejectionKind + "); containerd accepted"
		return result
	}
	if len(result.Differences) == 0 && len(result.ProducerToSilo) == 0 && len(result.ProducerToContainerd) == 0 {
		result.Status = "equal"
		return result
	}
	result.Status = "semantic-difference"
	// Root/default-directory metadata is an intentional policy difference, but
	// keep every field and both complete listings. Never drop directory rows.
	policy := true
	for _, set := range [][]Difference{result.Differences, result.ProducerToSilo, result.ProducerToContainerd} {
		for _, diff := range set {
			if diff.Path != "" {
				policy = false
				break
			}
		}
	}
	if policy {
		result.Status = "policy-difference"
	}
	return result
}

func reportMarkdown(report Report) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# OCI changeset extraction evidence\n\nExtractor: `%s`\n\nOptions: **archive.Apply defaults, no options**. No daemon or hypervisor.\n\nEnvironment and complete listings are retained in the adjacent JSON. None of the non-equal outcomes counts as equality.\n\n| Case | Outcome | Differences | First differing field / error |\n|---|---|---:|---|\n", report.Extractor)
	for _, result := range report.Results {
		detail := result.Error
		if len(result.Differences) > 0 {
			diff := result.Differences[0]
			detail = fmt.Sprintf("raw-path(base64url)=%s field=%s expected=%v actual=%v; %s", diff.Path, diff.Field, diff.Expected, diff.Actual, detail)
		}
		if len(result.CollectionErrors) > 0 {
			detail += strings.Join(result.CollectionErrors, "; ")
		}
		if len(result.ProducerOriginal) != 0 {
			detail += fmt.Sprintf("; producer-original->Silo=%d differences, producer-original->containerd=%d differences; source evidence=%s", len(result.ProducerToSilo), len(result.ProducerToContainerd), result.ProducerEvidence)
			if len(result.ProducerToSilo) > 0 {
				diff := result.ProducerToSilo[0]
				detail += fmt.Sprintf("; first producer->Silo path=%s field=%s expected=%v actual=%v", diff.Path, diff.Field, diff.Expected, diff.Actual)
			}
		}
		detail = strings.NewReplacer("|", "\\|", "\n", " ").Replace(detail)
		fmt.Fprintf(&out, "| %s | %s | %d | %s |\n", result.Name, result.Status, len(result.Differences), detail)
	}
	return out.String()
}

func applyCommand(args []string) (result error) {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	requestPath := flags.String("request", "", "fixture/acquisition request JSON")
	out := flags.String("out", "", "evidence output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *requestPath == "" || *out == "" {
		return fmt.Errorf("apply requires --request and --out")
	}
	var request Request
	if err := readJSON(*requestPath, &request); err != nil {
		return err
	}
	if request.Schema != 1 {
		return fmt.Errorf("unsupported request schema")
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		return err
	}
	temp, err := os.MkdirTemp(*out, "roots-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(temp)) }()
	report := Report{Schema: 1, Extractor: extractorVersion, Options: []string{}, Environment: environment(temp), Request: *requestPath, Results: make([]Result, 0)}
	ctx, cancel := context.WithTimeout(context.Background(), 290*time.Second)
	defer cancel()
	for _, item := range request.Cases {
		report.Results = append(report.Results, applyCase(ctx, filepath.Dir(*requestPath), temp, item))
	}
	if err := writeJSON(filepath.Join(*out, "differences.json"), report); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "differences.md"), []byte(reportMarkdown(report)), 0600)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: extractor apply|acquire|socket|metadata [options]")
		os.Exit(2)
	}
	if info, ok := debug.ReadBuildInfo(); !ok {
		fmt.Fprintln(os.Stderr, "missing Go dependency build evidence")
		os.Exit(1)
	} else {
		pinned := false
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/containerd/containerd/v2" && dependency.Version == "v2.4.2" && dependency.Replace == nil {
				pinned = true
			}
		}
		if !pinned {
			fmt.Fprintln(os.Stderr, "helper was not built with unmodified containerd v2.4.2")
			os.Exit(1)
		}
	}
	var err error
	switch os.Args[1] {
	case "apply":
		err = applyCommand(os.Args[2:])
	case "acquire":
		err = acquireCommand(os.Args[2:])
	case "socket":
		err = socketCommand(os.Args[2:])
	case "metadata":
		err = metadataCommand(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
