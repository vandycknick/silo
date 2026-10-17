package silo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestFilePathValidationBeforeNative(t *testing.T) {
	machine := &Machine{}
	for _, path := range []string{"", "relative/file"} {
		t.Run(path, func(t *testing.T) {
			_, statErr := machine.StatFile(context.Background(), path)
			_, dirErr := machine.CreateDirectory(context.Background(), path, CreateDirectoryOptions{})
			_, uploadErr := machine.UploadFile(context.Background(), path, bytes.NewReader(nil))
			_, downloadErr := machine.DownloadFile(context.Background(), path)
			for _, err := range []error{statErr, dirErr, uploadErr, downloadErr} {
				var sdkErr *Error
				if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrorInvalidArgument || sdkErr.Message != "guest paths must be absolute" {
					t.Fatalf("validation error = %#v", err)
				}
			}
		})
	}
}
func TestFileModeValidationBeforeNative(t *testing.T) {
	machine := &Machine{}
	mode := uint32(0o10000)
	_, uploadErr := machine.UploadFile(context.Background(), "/tmp/x", bytes.NewReader(nil), WithFileMode(mode))
	_, dirErr := machine.CreateDirectory(context.Background(), "/tmp/x", CreateDirectoryOptions{Mode: &mode})
	for _, err := range []error{uploadErr, dirErr} {
		var sdkErr *Error
		if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrorInvalidArgument || sdkErr.Message != "mode must be a Unix permission value no greater than 0o7777" {
			t.Fatalf("validation error = %#v", err)
		}
	}
	for _, mode := range []uint32{0, 0o644, 0o7777} {
		if err := validateFileMode(&mode); err != nil {
			t.Fatal(err)
		}
	}
}
func TestFileOwnerOptions(t *testing.T) {
	gid := uint32(100)
	config := uploadConfig{}
	WithFileOwner(42, &gid)(&config)
	gid = 200
	if *config.UID != 42 || *config.GID != 100 {
		t.Fatalf("owner = %#v", config)
	}
	WithFileOwner(43, nil)(&config)
	if *config.UID != 43 || config.GID != nil {
		t.Fatalf("owner without group = %#v", config)
	}
}
func TestClosedFileDownload(t *testing.T) {
	var reader io.ReadCloser = &FileDownload{closed: true}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := reader.Read(make([]byte, 1))
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrorClosed {
		t.Fatalf("closed error = %#v", err)
	}
}
