package silo

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

// FileEntryKind identifies the guest filesystem entry type.
type FileEntryKind string

const (
	FileEntryFile            FileEntryKind = "file"
	FileEntryDirectory       FileEntryKind = "directory"
	FileEntrySymlink         FileEntryKind = "symlink"
	FileEntryFIFO            FileEntryKind = "fifo"
	FileEntrySocket          FileEntryKind = "socket"
	FileEntryBlockDevice     FileEntryKind = "block_device"
	FileEntryCharacterDevice FileEntryKind = "character_device"
)

type FileEntry struct {
	Path, Name     string
	Kind           FileEntryKind
	SizeBytes      uint64
	Mode, UID, GID uint32
	ModifiedAt     time.Time
}
type DirectoryDisposition string

const (
	DirectoryCreated       DirectoryDisposition = "created"
	DirectoryAlreadyExists DirectoryDisposition = "already_exists"
)

type FileWriteDisposition string

const (
	FileCreated  FileWriteDisposition = "created"
	FileReplaced FileWriteDisposition = "replaced"
)

type CreateDirectoryOptions struct {
	Parents        bool
	Mode, UID, GID *uint32
}
type uploadConfig struct {
	Path string  `json:"path"`
	Mode *uint32 `json:"mode,omitempty"`
	UID  *uint32 `json:"uid,omitempty"`
	GID  *uint32 `json:"gid,omitempty"`
}
type UploadOption func(*uploadConfig)

func WithFileMode(mode uint32) UploadOption { return func(c *uploadConfig) { c.Mode = &mode } }
func WithFileOwner(uid uint32, gid *uint32) UploadOption {
	return func(c *uploadConfig) {
		c.UID = &uid
		if gid != nil {
			value := *gid
			c.GID = &value
		} else {
			c.GID = nil
		}
	}
}

type UploadResult struct {
	Disposition FileWriteDisposition
	Bytes       int64
}

func validateFilePath(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") {
		return newError(ErrorInvalidArgument, "", "guest paths must be absolute")
	}
	if strings.ContainsRune(path, 0) {
		return newError(ErrorInvalidArgument, "", "guest paths must not contain NUL")
	}
	return nil
}
func validateFileMode(mode *uint32) error {
	if mode != nil && *mode > 0o7777 {
		return newError(ErrorInvalidArgument, "", "mode must be a Unix permission value no greater than 0o7777")
	}
	return nil
}
func fileRequest(path string, mode *uint32, value interface{}) ([]byte, error) {
	if err := validateFilePath(path); err != nil {
		return nil, err
	}
	if err := validateFileMode(mode); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
func machineFileCall[T interface{}](m *Machine, ctx context.Context, call func(*ffi.Machine) (T, error)) (T, error) {
	var zero T
	if err := validateContext(ctx); err != nil {
		return zero, err
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return zero, newError(ErrorClosed, "", "machine is closed")
	}
	value, err := call(m.native)
	return value, fromNativeError(err)
}

// StatFile returns metadata without following a guest symlink.
func (m *Machine) StatFile(ctx context.Context, path string) (*FileEntry, error) {
	request, err := fileRequest(path, nil, struct {
		Path string `json:"path"`
	}{path})
	if err != nil {
		return nil, err
	}
	data, err := machineFileCall(m, ctx, func(native *ffi.Machine) ([]byte, error) { return native.MachineFileStat(request) })
	if err != nil {
		return nil, err
	}
	var wire struct {
		Path                 string        `json:"path"`
		Name                 string        `json:"name"`
		Kind                 FileEntryKind `json:"kind"`
		SizeBytes            uint64        `json:"size_bytes"`
		Mode                 uint32        `json:"mode"`
		UID                  uint32        `json:"uid"`
		GID                  uint32        `json:"gid"`
		ModifiedAtUnixMillis int64         `json:"modified_at_unix_millis"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, newError(ErrorUnknown, "", "decode file entry: "+err.Error())
	}
	return &FileEntry{Path: wire.Path, Name: wire.Name, Kind: wire.Kind, SizeBytes: wire.SizeBytes, Mode: wire.Mode, UID: wire.UID, GID: wire.GID, ModifiedAt: time.UnixMilli(wire.ModifiedAtUnixMillis)}, nil
}
func (m *Machine) CreateDirectory(ctx context.Context, path string, opts CreateDirectoryOptions) (DirectoryDisposition, error) {
	request, err := fileRequest(path, opts.Mode, struct {
		Path    string  `json:"path"`
		Parents bool    `json:"parents"`
		Mode    *uint32 `json:"mode,omitempty"`
		UID     *uint32 `json:"uid,omitempty"`
		GID     *uint32 `json:"gid,omitempty"`
	}{path, opts.Parents, opts.Mode, opts.UID, opts.GID})
	if err != nil {
		return "", err
	}
	data, err := machineFileCall(m, ctx, func(native *ffi.Machine) ([]byte, error) { return native.MachineCreateDirectory(request) })
	if err != nil {
		return "", err
	}
	disposition, err := decodeFileDisposition(data)
	return DirectoryDisposition(disposition), err
}
func decodeFileDisposition(data []byte) (string, error) {
	var wire struct {
		Disposition string `json:"disposition"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return "", newError(ErrorUnknown, "", "decode file disposition: "+err.Error())
	}
	return wire.Disposition, nil
}
func transferCall[T interface{}](ctx context.Context, cancel func() error, call func() (T, error)) (T, error) {
	var zero T
	if err := validateContext(ctx); err != nil {
		return zero, err
	}
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() { value, err := call(); done <- result{value, err} }()
	select {
	case result := <-done:
		return result.value, fromNativeError(result.err)
	case <-ctx.Done():
		_ = cancel()
		<-done
		return zero, contextError(ctx.Err())
	}
}

// UploadFile atomically replaces a regular guest file. A source Read must return
// before cancellation can complete; arbitrary io.Readers cannot be interrupted.
func (m *Machine) UploadFile(ctx context.Context, path string, source io.Reader, opts ...UploadOption) (UploadResult, error) {
	config := uploadConfig{Path: path}
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}
	request, err := fileRequest(path, config.Mode, config)
	if err != nil {
		return UploadResult{}, err
	}
	if source == nil {
		return UploadResult{}, newError(ErrorInvalidArgument, "", "upload source must not be nil")
	}
	upload, err := machineFileCall(m, ctx, func(native *ffi.Machine) (*ffi.Upload, error) { return native.MachineUploadOpen(request) })
	if err != nil {
		return UploadResult{}, err
	}
	defer upload.UploadFree()
	defer upload.UploadCancel()
	buffer := make([]byte, 65536)
	var result UploadResult
	emptyReads := 0
	for {
		if err := validateContext(ctx); err != nil {
			return result, err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			emptyReads = 0
			_, err = transferCall(ctx, upload.UploadCancel, func() (struct{}, error) { return struct{}{}, upload.UploadWrite(buffer[:n]) })
			if err != nil {
				return result, err
			}
			result.Bytes += int64(n)
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return result, io.ErrNoProgress
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	data, err := transferCall(ctx, upload.UploadCancel, upload.UploadFinish)
	if err != nil {
		return result, err
	}
	disposition, err := decodeFileDisposition(data)
	result.Disposition = FileWriteDisposition(disposition)
	return result, err
}

// FileDownload permits one Read at a time. Close may interrupt an active Read.
type FileDownload struct {
	mutex       sync.Mutex
	reader      sync.Mutex
	native      *ffi.Download
	ctx         context.Context
	chunk       []byte
	eof, closed bool
}

func (m *Machine) DownloadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	request, err := fileRequest(path, nil, struct {
		Path string `json:"path"`
	}{path})
	if err != nil {
		return nil, err
	}
	native, err := machineFileCall(m, ctx, func(native *ffi.Machine) (*ffi.Download, error) { return native.MachineDownloadOpen(request) })
	if err != nil {
		return nil, err
	}
	return &FileDownload{native: native, ctx: ctx}, nil
}
func (d *FileDownload) Read(p []byte) (int, error) {
	d.reader.Lock()
	defer d.reader.Unlock()
	d.mutex.Lock()
	if d.closed {
		d.mutex.Unlock()
		return 0, newError(ErrorClosed, "", "file download is closed")
	}
	native := d.native
	d.mutex.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(d.chunk) == 0 && !d.eof {
		type chunk struct {
			data []byte
			eof  bool
		}
		result, err := transferCall(d.ctx, native.DownloadCancel, func() (chunk, error) { data, eof, err := native.DownloadRead(); return chunk{data, eof}, err })
		if err != nil {
			return 0, err
		}
		d.chunk, d.eof = result.data, result.eof
	}
	n := copy(p, d.chunk)
	d.chunk = d.chunk[n:]
	if n == 0 && d.eof {
		return 0, io.EOF
	}
	return n, nil
}
func (d *FileDownload) Close() error {
	if d == nil {
		return nil
	}
	d.mutex.Lock()
	if d.closed {
		d.mutex.Unlock()
		return nil
	}
	d.closed = true
	err := d.native.DownloadCancel()
	d.mutex.Unlock()
	d.reader.Lock()
	defer d.reader.Unlock()
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.native.DownloadFree()
	d.native = nil
	d.chunk = nil
	return fromNativeError(err)
}
