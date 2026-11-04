//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// This is raw wire evidence, not a producer-dialect inference. RawRecord includes
// the length prefix and the entire original record, including binary values.
type PAXObservation struct {
	HeaderOffset int64  `json:"headerOffset"`
	Scope        string `json:"scope"`
	HeaderName   string `json:"headerName"`
	Key          string `json:"key"`
	Value        string `json:"value"`
	RawRecord    string `json:"rawRecord"`
}

type ProducerTool struct {
	Producer         string `json:"producer"`
	Executable       string `json:"executable"`
	ExecutableDigest string `json:"executableDigest,omitempty"`
	Version          string `json:"version"`
	VersionError     string `json:"versionError,omitempty"`
	Error            string `json:"error,omitempty"`
}

type ProducerObservation struct {
	Name                     string           `json:"name"`
	Tool                     ProducerTool     `json:"tool"`
	CreateArguments          []string         `json:"createArguments"`
	ExtractArguments         []string         `json:"extractArguments"`
	Stage                    string           `json:"stage"`
	Status                   string           `json:"status"`
	Error                    string           `json:"error,omitempty"`
	Archive                  string           `json:"archive"`
	ArchiveDigest            string           `json:"archiveDigest,omitempty"`
	ArchiveLength            int64            `json:"archiveLength"`
	WireRecords              []PAXObservation `json:"wireRecords"`
	WireInspectionError      string           `json:"wireInspectionError,omitempty"`
	SourceBefore             []Row            `json:"sourceBefore"`
	SourceAfter              []Row            `json:"sourceAfter"`
	SourceChanges            []Difference     `json:"sourceChanges"`
	InitialSourceDifferences []Difference     `json:"initialSourceDifferences"`
	ArchivedOriginal         []Row            `json:"archivedOriginal"`
	Extracted                []Row            `json:"extracted"`
	Differences              []Difference     `json:"differences"`
	CollectionErrors         []string         `json:"collectionErrors"`
}

type MetadataReport struct {
	Schema             int                   `json:"schema"`
	Purpose            string                `json:"purpose"`
	IntendedAttributes []Attribute           `json:"intendedAttributes"`
	ProducerOriginal   []Row                 `json:"producerOriginal"`
	SourceErrors       []string              `json:"sourceErrors"`
	Environment        map[string]any        `json:"environment"`
	StarSource         any                   `json:"starSource"`
	StarBuild          any                   `json:"starBuild"`
	Producers          []ProducerObservation `json:"producers"`
}

func wireOctal(field []byte) (int64, error) {
	text := strings.Trim(string(field), " \x00")
	if text == "" {
		return 0, nil
	}
	for _, ch := range text {
		if ch < '0' || ch > '7' {
			return 0, fmt.Errorf("non-octal numeric field in producer wire evidence")
		}
	}
	return strconv.ParseInt(text, 8, 64)
}

func inspectProducerPAX(path string) ([]PAXObservation, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	observed := make([]PAXObservation, 0)
	var offset int64
	var zero [512]byte
	for {
		var header [512]byte
		if _, err := io.ReadFull(file, header[:]); err != nil {
			return observed, err
		}
		if header == zero {
			return observed, nil
		}
		expected, err := wireOctal(header[148:156])
		if err != nil {
			return observed, err
		}
		var sum int64
		for index, value := range header {
			if index >= 148 && index < 156 {
				sum += ' '
			} else {
				sum += int64(value)
			}
		}
		if sum != expected {
			return observed, fmt.Errorf("producer header checksum mismatch at %d", offset)
		}
		size, err := wireOctal(header[124:136])
		if err != nil || size < 0 {
			return observed, fmt.Errorf("producer header size: %v", err)
		}
		name := bytes.TrimRight(header[:100], "\x00")
		if header[156] == 'x' || header[156] == 'g' {
			if size > 4<<20 {
				return observed, fmt.Errorf("producer PAX evidence exceeds 4 MiB inspection bound")
			}
			body := make([]byte, int(size))
			if _, err := io.ReadFull(file, body); err != nil {
				return observed, err
			}
			for cursor := 0; cursor < len(body); {
				space := bytes.IndexByte(body[cursor:], ' ')
				if space < 1 {
					return observed, fmt.Errorf("producer PAX length prefix")
				}
				text := body[cursor : cursor+space]
				for _, ch := range text {
					if ch < '0' || ch > '9' {
						return observed, fmt.Errorf("producer PAX nondecimal length")
					}
				}
				length, err := strconv.Atoi(string(text))
				if err != nil || length <= space+2 || length > len(body)-cursor {
					return observed, fmt.Errorf("producer PAX record length")
				}
				record := body[cursor : cursor+length]
				if record[len(record)-1] != '\n' {
					return observed, fmt.Errorf("producer PAX missing record terminator")
				}
				payload := record[space+1 : len(record)-1]
				equal := bytes.IndexByte(payload, '=')
				if equal < 1 {
					return observed, fmt.Errorf("producer PAX key/value framing")
				}
				scope := "local"
				if header[156] == 'g' {
					scope = "global"
				}
				observed = append(observed, PAXObservation{HeaderOffset: offset, Scope: scope, HeaderName: b64(name), Key: b64(payload[:equal]), Value: b64(payload[equal+1:]), RawRecord: b64(record)})
				cursor += length
			}
		} else if _, err := io.CopyN(io.Discard, file, size); err != nil {
			return observed, err
		}
		padding := (512 - size%512) % 512
		if _, err := io.CopyN(io.Discard, file, padding); err != nil {
			return observed, err
		}
		offset += 512 + size + padding
	}
}

func producerRun(ctx context.Context, executable, directory, log string, args []string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if writeErr := os.WriteFile(log, output, 0600); writeErr != nil {
		return writeErr
	}
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	return err
}

func producerTool(ctx context.Context, output, name, executable string) ProducerTool {
	tool := ProducerTool{Producer: name, Executable: executable}
	resolved, err := exec.LookPath(executable)
	if err != nil {
		tool.Error = err.Error()
		return tool
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		tool.Error = err.Error()
		return tool
	}
	tool.Executable = resolved
	tool.ExecutableDigest, err = fileDigest(resolved)
	if err != nil {
		tool.Error = err.Error()
		return tool
	}
	args := []string{"--version"}
	if name == "star" {
		args = []string{"-version"}
	}
	command := exec.CommandContext(ctx, resolved, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	version, versionErr := command.CombinedOutput()
	tool.Version = string(version)
	if err := os.WriteFile(filepath.Join(output, name+"-version.log"), version, 0600); err != nil {
		tool.Error = err.Error()
		return tool
	}
	if versionErr != nil {
		tool.VersionError = versionErr.Error()
	}
	return tool
}

func producerMetadata(ctx context.Context, output, source, specimen string, tool ProducerTool, files []string, original []Row) (result ProducerObservation) {
	name := tool.Producer + "-" + specimen
	before, problems := collect(source)
	selected := make(map[string]bool, len(files)+1)
	selected[""] = true
	for _, file := range files {
		selected[b64([]byte(file))] = true
	}
	archived := make([]Row, 0, len(files)+1)
	for _, row := range before {
		if selected[row.Path] {
			archived = append(archived, row)
		}
	}
	result = ProducerObservation{Name: name, Tool: tool, Archive: name + ".tar", Stage: "create", Status: "environment-unavailable", SourceBefore: before, InitialSourceDifferences: differences(original, before), ArchivedOriginal: archived, SourceAfter: []Row{}, SourceChanges: []Difference{}, WireRecords: []PAXObservation{}, Extracted: []Row{}, Differences: []Difference{}, CollectionErrors: problems}
	if len(problems) > 0 {
		return result
	}
	if tool.Error != "" {
		result.Error = tool.Error
		return result
	}
	archive := filepath.Join(output, result.Archive)
	switch tool.Producer {
	case "gnu-tar":
		result.CreateArguments = []string{"--create", "--format=pax", "--xattrs", "--xattrs-include=*", "--file", archive}
		result.ExtractArguments = []string{"--extract", "--xattrs", "--xattrs-include=*", "--file", archive}
	case "libarchive":
		result.CreateArguments = []string{"-c", "--format=pax", "--xattrs", "-f", archive}
		result.ExtractArguments = []string{"-x", "--xattrs", "-f", archive}
	case "star":
		result.CreateArguments = []string{"-c", "H=exustar", "-xattr-linux", "-f", archive}
		result.ExtractArguments = []string{"-x", "-xattr-linux", "-f", archive}
	default:
		result.Error = "unknown producer"
		return result
	}
	result.CreateArguments = append(result.CreateArguments, files...)
	createErr := producerRun(ctx, tool.Executable, source, filepath.Join(output, name+"-create.log"), result.CreateArguments)
	result.SourceAfter, result.CollectionErrors = collect(source)
	result.SourceChanges = differences(before, result.SourceAfter)
	info, statErr := os.Stat(archive)
	if statErr == nil {
		result.ArchiveLength = info.Size()
		var hashErr error
		result.ArchiveDigest, hashErr = fileDigest(archive)
		if hashErr != nil {
			result.CollectionErrors = append(result.CollectionErrors, hashErr.Error())
		}
		records, inspectErr := inspectProducerPAX(archive)
		result.WireRecords = records
		if inspectErr != nil {
			result.WireInspectionError = inspectErr.Error()
		}
	}
	if createErr != nil {
		result.Status = "producer-rejected"
		if unavailable(createErr) {
			result.Status = "environment-unavailable"
		}
		result.Error = createErr.Error()
		return result
	}
	if statErr != nil {
		result.Error = statErr.Error()
		return result
	}
	root, err := os.MkdirTemp(output, name+"-extract-")
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			result.Status = "environment-unavailable"
			result.CollectionErrors = append(result.CollectionErrors, "cleanup: "+err.Error())
		}
	}()
	result.Stage = "extract"
	extractErr := producerRun(ctx, tool.Executable, root, filepath.Join(output, name+"-extract.log"), result.ExtractArguments)
	rows, problems := collect(root)
	result.Extracted = rows
	result.CollectionErrors = append(result.CollectionErrors, problems...)
	result.Differences = differences(archived, rows)
	if extractErr != nil {
		result.Status = "extraction-rejected"
		if unavailable(extractErr) {
			result.Status = "environment-unavailable"
		}
		result.Error = extractErr.Error()
		return result
	}
	if len(result.CollectionErrors) > 0 || tool.VersionError != "" {
		result.Status = "environment-unavailable"
		return result
	}
	result.Status = "equal"
	if result.WireInspectionError != "" || len(result.SourceChanges) > 0 || len(result.InitialSourceDifferences) > 0 {
		result.Status = "semantic-difference"
	}
	if len(result.Differences) > 0 {
		if result.Status == "equal" {
			result.Status = "policy-difference"
		}
		for _, diff := range result.Differences {
			if diff.Path != "" {
				result.Status = "semantic-difference"
				break
			}
		}
	}
	return result
}

func metadataCommand(args []string) (result error) {
	flags := flag.NewFlagSet("metadata", flag.ContinueOnError)
	star := flags.String("star", "", "pinned-source star executable")
	sourcePin := flags.String("source-pin", "", "retained exact star source pin")
	buildEvidence := flags.String("build-evidence", "", "recorded source/compiler/flags JSON")
	out := flags.String("out", "", "new producer-original output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *star == "" || *sourcePin == "" || *buildEvidence == "" || *out == "" {
		return fmt.Errorf("metadata requires --star --source-pin --build-evidence --out")
	}
	output, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return fmt.Errorf("metadata output must be new: %w", err)
	}
	source, err := os.MkdirTemp(output, "producer-source-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(source)) }()
	report := MetadataReport{Schema: 1, Purpose: "Producer-original raw xattr intent, unmodified tar wire bytes, actual same-tool extraction and separate Silo/containerd comparisons. Extractor agreement alone is not evidence of producer-original names.", IntendedAttributes: []Attribute{}, ProducerOriginal: []Row{}, SourceErrors: []string{}, Environment: environment(output), Producers: []ProducerObservation{}}
	if err := readJSON(*sourcePin, &report.StarSource); err != nil {
		return err
	}
	if err := readJSON(*buildEvidence, &report.StarBuild); err != nil {
		return err
	}
	names := [][]byte{[]byte("user.a=b"), []byte("user.a%b"), []byte("user.a%3Db"), []byte("user.a%25b"), []byte("user.a b"), []byte("user.\xc3\xa9"), []byte("user.\xff"), []byte("user.a+b"), []byte("user.empty")}
	files := make([]string, 0, len(names)+1)
	for index, name := range names {
		value := []byte{0, 255, 10, '='}
		if string(name) == "user.empty" {
			value = []byte{}
		}
		report.IntendedAttributes = append(report.IntendedAttributes, Attribute{Name: b64(name), Value: b64(value)})
		filename := fmt.Sprintf("file-%02d", index)
		files = append(files, filename)
		path := filepath.Join(source, filename)
		if err := os.WriteFile(path, []byte("producer-original\n"), 0644); err != nil {
			return err
		}
		if err := unix.Lsetxattr(path, string(name), value, 0); err != nil {
			report.SourceErrors = append(report.SourceErrors, fmt.Sprintf("set source raw name %s: %v", b64(name), err))
		}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{{Sec: 1, Nsec: 7}, {Sec: 1, Nsec: 7}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	}
	complete := filepath.Join(source, "complete-set")
	files = append(files, "complete-set")
	if err := os.WriteFile(complete, []byte("complete original attribute set\n"), 0644); err != nil {
		return err
	}
	for _, attribute := range report.IntendedAttributes {
		name, err := base64.RawURLEncoding.DecodeString(attribute.Name)
		if err != nil {
			return err
		}
		value, err := base64.RawURLEncoding.DecodeString(attribute.Value)
		if err != nil {
			return err
		}
		if err := unix.Lsetxattr(complete, string(name), value, 0); err != nil {
			report.SourceErrors = append(report.SourceErrors, fmt.Sprintf("set complete raw name %s: %v", attribute.Name, err))
		}
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, complete, []unix.Timespec{{Sec: 1, Nsec: 7}, {Sec: 1, Nsec: 7}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := os.Chmod(source, 0755); err != nil {
		return err
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, source, []unix.Timespec{{Sec: 1}, {Sec: 1}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	original, problems := collect(source)
	report.ProducerOriginal = original
	report.SourceErrors = append(report.SourceErrors, problems...)
	request := Request{Schema: 1, Cases: []Case{}}
	if len(report.SourceErrors) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 290*time.Second)
		defer cancel()
		for _, producer := range []struct{ name, executable string }{{"gnu-tar", "tar"}, {"libarchive", "bsdtar"}, {"star", *star}} {
			tool := producerTool(ctx, output, producer.name, producer.executable)
			for index, specimen := range files {
				selected := files[index : index+1]
				if specimen == "complete-set" {
					selected = files
				}
				observed := producerMetadata(ctx, output, source, specimen, tool, selected, original)
				report.Producers = append(report.Producers, observed)
				if observed.ArchiveDigest != "" {
					request.Cases = append(request.Cases, Case{Name: "producer-original-" + observed.Name, Producer: tool.Producer, ProducerEvidence: "producers.json", ProducerOriginal: observed.ArchivedOriginal, Expected: []Row{}, Layers: []Layer{{Tar: observed.Archive, Blob: observed.Archive, Digest: observed.ArchiveDigest, Size: observed.ArchiveLength, MediaType: "application/vnd.oci.image.layer.v1.tar", DiffID: observed.ArchiveDigest}}})
				}
			}
		}
	}
	if err := writeJSON(filepath.Join(output, "producers.json"), report); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(output, "acquired.json"), request); err != nil {
		return err
	}
	var markdown strings.Builder
	markdown.WriteString("# Producer-original raw xattr evidence\n\nSource names/values were set on real Linux inodes and independently collected before/after archiving. The retained original complete attribute set, raw length-framed PAX records, archive hashes and actual extraction listings are authoritative evidence. No producer dialect is guessed from incidental tar headers. In particular, agreement between Silo and an extractor does not prove agreement with the original inode.\n\n| Producer | Stage | Outcome | Original-to-extracted differences | Error |\n|---|---|---|---:|---|\n")
	for _, producer := range report.Producers {
		fmt.Fprintf(&markdown, "| %s | %s | %s | %d | %s |\n", producer.Name, producer.Stage, producer.Status, len(producer.Differences), strings.NewReplacer("|", "\\|", "\n", " ").Replace(producer.Error+" "+producer.WireInspectionError))
	}
	if len(report.SourceErrors) > 0 {
		fmt.Fprintf(&markdown, "\nSource environment unavailable: %v\n", report.SourceErrors)
	}
	markdown.WriteString("\nRun the separate qualify-changesets --acquired command on this directory. Its JSON+Markdown retains producer-original->Silo, producer-original->containerd and Silo->containerd differences separately, including typed Silo ambiguity rejection. A matching round trip cannot identify the intent of wire-identical raw/escaped SCHILY records.\n")
	return os.WriteFile(filepath.Join(output, "producers.md"), []byte(markdown.String()), 0600)
}
