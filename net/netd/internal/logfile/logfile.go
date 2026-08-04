// Package logfile opens netd-owned log files beneath validated directories.
package logfile

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const fileMode = 0o600
const directoryMode = 0o700

type Directory struct {
	file *os.File
}

// OpenDirectory takes ownership of an inherited directory descriptor after
// validating its type, owner, and exact mode.
func OpenDirectory(fd int) (*Directory, error) {
	if fd < 0 {
		return nil, errors.New("directory descriptor must be non-negative")
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("directory fd %d", fd))
	if file == nil {
		return nil, fmt.Errorf("directory fd %d: create file handle", fd)
	}
	if err := validateDirectory(fd); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("directory fd %d: %w", fd, err)
	}
	return &Directory{file: file}, nil
}

func (d *Directory) OpenAppend(name string) (*os.File, error) {
	return d.open(name, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW)
}

// OpenTruncate opens name as a private regular file and truncates it after
// validating the opened descriptor.
func (d *Directory) OpenTruncate(name string) (*os.File, error) {
	file, err := d.open(name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	if err := unix.Ftruncate(int(file.Fd()), 0); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("truncate %s: %w", name, err), closeErr)
	}
	return file, nil
}

// Write replaces a private regular file after validating the opened descriptor.
func (d *Directory) Write(name string, contents []byte) error {
	file, err := d.OpenTruncate(name)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", name, err), SyncClose(file))
	}
	return SyncClose(file)
}

func (d *Directory) Remove(name string) error {
	if err := validLeafName(name); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(d.file.Fd()), name, 0); err != nil {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

func (d *Directory) Close() error {
	if d == nil || d.file == nil {
		return nil
	}
	return d.file.Close()
}

// SyncClose persists pending data before closing file.
func SyncClose(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(file.Sync(), file.Close())
}

func (d *Directory) open(name string, flags int) (*os.File, error) {
	if d == nil || d.file == nil {
		return nil, errors.New("log directory is not configured")
	}
	if err := validLeafName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags|unix.O_CREAT|unix.O_EXCL, fileMode)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(d.file.Fd()), name, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s: create file handle", name)
	}
	if created {
		if err := unix.Fchmod(fd, fileMode); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("open %s: set log permissions: %w", name, err)
		}
	}
	if err := validate(fd); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return file, nil
}

func validLeafName(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("file name %q is not one path component", name)
	}
	return nil
}

func validateDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat descriptor: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("target is not a directory")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("target is not owned by the effective user")
	}
	if stat.Mode&0o7777 != directoryMode {
		return fmt.Errorf("target has mode %04o, want %04o", stat.Mode&0o7777, directoryMode)
	}
	return nil
}

func validate(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat descriptor: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("log target is not a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("log target is not owned by the effective user")
	}
	if stat.Mode&0o7777 != fileMode {
		return fmt.Errorf("log target has mode %04o, want %04o", stat.Mode&0o7777, fileMode)
	}
	return nil
}
