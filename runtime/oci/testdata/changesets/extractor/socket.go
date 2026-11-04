//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}
func starRun(ctx context.Context, star, dir, log string, args ...string) error {
	command := exec.CommandContext(ctx, star, args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if writeErr := os.WriteFile(log, output, 0600); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return fmt.Errorf("star %v: %w (see %s)", args, err, log)
	}
	return nil
}

func socketCommand(args []string) error {
	flags := flag.NewFlagSet("socket", flag.ContinueOnError)
	star := flags.String("star", "", "star executable built from the pinned source")
	sourcePin := flags.String("source-pin", "", "retained exact source provenance JSON")
	buildEvidence := flags.String("build-evidence", "", "recorded source/compiler/flags JSON")
	out := flags.String("out", "", "new socket specimen output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *star == "" || *out == "" || *sourcePin == "" || *buildEvidence == "" {
		return fmt.Errorf("socket requires --star --source-pin --build-evidence --out")
	}
	binary, err := filepath.Abs(*star)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return fmt.Errorf("socket output must be new: %w", err)
	}
	source, err := os.MkdirTemp("", "silo-socket-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(source)
	extracted, err := os.MkdirTemp(output, "star-extracted-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(extracted)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	path := filepath.Join(source, "socket")
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return err
	}
	if err := os.Chmod(path, 0755); err != nil {
		return err
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{{Sec: 1, Nsec: 7}, {Sec: 1, Nsec: 7}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	sourceRows, sourceErrors := collect(source)
	if len(sourceErrors) > 0 {
		return fmt.Errorf("source socket collection: %v", sourceErrors)
	}
	sourceSocket := false
	for _, row := range sourceRows {
		if row.Path == b64([]byte("socket")) && row.Kind == "socket" {
			sourceSocket = true
		}
	}
	if !sourceSocket {
		return fmt.Errorf("source lstat did not report S_IFSOCK")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 290*time.Second)
	defer cancel()
	archivePath := filepath.Join(output, "socket.tar")
	createArgs := []string{"-c", "H=exustar", "-dump", "-f", archivePath, "socket"}
	extractArgs := []string{"-x", "-f", archivePath}
	if err := starRun(ctx, binary, source, filepath.Join(output, "star-create.log"), createArgs...); err != nil {
		return err
	}
	if err := starRun(ctx, binary, extracted, filepath.Join(output, "star-extract.log"), extractArgs...); err != nil {
		return err
	}
	rows, collectionErrors := collect(extracted)
	extractedSocket := false
	for _, row := range rows {
		if row.Path == b64([]byte("socket")) && row.Kind == "socket" {
			extractedSocket = true
		}
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	reader := tar.NewReader(file)
	documented := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			file.Close()
			return err
		}
		if header.Name == "socket" && header.Typeflag == tar.TypeReg && header.Size == 0 && header.PAXRecords["SCHILY.filetype"] == "socket" {
			documented = true
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	if !documented || !extractedSocket || len(collectionErrors) > 0 {
		return fmt.Errorf("independent socket proof failed: documented PAX=%v S_IFSOCK=%v errors=%v", documented, extractedSocket, collectionErrors)
	}
	digest, err := fileDigest(archivePath)
	if err != nil {
		return err
	}
	binaryDigest, err := fileDigest(binary)
	if err != nil {
		return err
	}
	pin, err := os.ReadFile(*sourcePin)
	if err != nil {
		return err
	}
	var version bytes.Buffer
	command := exec.CommandContext(ctx, binary, "-version")
	command.Stdout = &version
	command.Stderr = &version
	versionErr := command.Run()
	provenance := map[string]any{"schema": 1, "sourcePin": string(pin), "binaryDigest": binaryDigest, "binaryVersion": version.String(), "versionExit": fmt.Sprint(versionErr), "createArguments": createArgs, "extractArguments": extractArgs, "archiveDigest": digest, "sourceListing": sourceRows, "starExtractedListing": rows, "collectionErrors": collectionErrors, "differences": differences(sourceRows, rows), "environment": environment(output), "proof": "real AF_UNIX bind; upstream star archive+independent extract; lstat S_IFSOCK; effective zero-byte regular SCHILY.filetype=socket member; no IPC state"}
	var build any
	if err := readJSON(*buildEvidence, &build); err != nil {
		return err
	}
	provenance["build"] = build
	if err := writeJSON(filepath.Join(output, "provenance.json"), provenance); err != nil {
		return err
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return err
	}
	item := Case{Name: "star-real-socket", Expected: rows, Layers: []Layer{{Tar: "socket.tar", Blob: "socket.tar", Digest: digest, Size: info.Size(), MediaType: "application/vnd.oci.image.layer.v1.tar", DiffID: digest}}}
	if err := writeJSON(filepath.Join(output, "acquired.json"), Request{Schema: 1, Cases: []Case{item}}); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "provenance.md"), []byte("# Independent real socket specimen\n\nA real Linux AF_UNIX socket was archived with pinned schilytools/star exustar dump and independently extracted with star. Both were collected using lstat, not by the Silo decoder. Source/extracted root metadata and any differences remain in provenance.json; no field is filtered. The archive retains upstream dev/inode/nlink/ctime facts, so regenerating the specimen is acquisition, not a reproducible tar claim. Re-ingesting the retained exact archive must be fully repeatable. Containerd's socket-as-regular behavior is measured separately by the named comparison command.\n"), 0600)
}
