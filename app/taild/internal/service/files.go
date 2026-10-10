package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	silo "github.com/vandycknick/silo/sdk/go"
)

type CopyRequest struct {
	VM                 string
	Path               string
	Upload             bool
	Mode, UID, GID     *uint32
	Parents, NoClobber bool
}
type CopySummary struct {
	Bytes               int64
	SHA256, Disposition string
}

type fileContextReader struct {
	ctx    context.Context
	reader interface {
		ReadContext(context.Context, []byte) (int, error)
	}
}

func (r fileContextReader) Read(p []byte) (int, error) {
	return r.reader.ReadContext(r.ctx, p)
}

// transferReader rejects the extra byte before UploadFile can commit its temporary file.
type transferReader struct {
	source    io.Reader
	remaining int64
	exceeded  bool
}

func (r *transferReader) Read(p []byte) (int, error) {
	n, e := r.source.Read(p)
	if int64(n) > r.remaining {
		r.exceeded = true
		return 0, failure("limit", "upload exceeds the operator file transfer limit", 6)
	}
	r.remaining -= int64(n)
	return n, e
}

func (s *Service) copyMachine(ctx context.Context, c Caller, q CopyRequest) (*silo.Machine, string, error) {
	p, e := c.Fresh(ctx)
	if e != nil {
		return nil, "", e
	}
	d, e := s.inspect(ctx, p, q.VM, identity.Files)
	if e != nil {
		return nil, "", e
	}
	if d.Status.Kind != silo.MachineStatusRunning {
		return nil, "", failure("conflict", "cp requires a running VM", 5)
	}
	m, e := s.Runtime.Machine(ctx, d.ID)
	if e != nil {
		return nil, "", Categorize(e)
	}
	return m, d.ID, nil
}
func (s *Service) CopyToVM(parent context.Context, c Caller, q CopyRequest, source io.Reader) (summary CopySummary, err error) {
	m, id, e := s.copyMachine(parent, c, q)
	if e != nil {
		return summary, e
	}
	defer s.Runtime.CloseMachine(m)
	ctx, cancel, recheck := s.streamContext(parent, c, id, identity.Files)
	defer cancel()
	defer func() {
		if denied := recheck(); denied != nil {
			err = denied
		}
	}()
	entry, e := m.StatFile(ctx, q.Path)
	var native *silo.Error
	missing := errors.As(e, &native) && native.Kind == silo.ErrorGuestPathNotFound
	if e != nil && !missing {
		return summary, Categorize(e)
	}
	if e == nil {
		if q.NoClobber {
			return summary, failure("conflict", fmt.Sprintf("%s:%s exists", q.VM, q.Path), 5)
		}
		if entry.Kind == silo.FileEntryDirectory {
			return summary, failure("usage", "destination is a directory; give the full target path", 2)
		}
	}
	if q.Parents && path.Dir(q.Path) != "/" {
		if _, e = m.CreateDirectory(ctx, path.Dir(q.Path), silo.CreateDirectoryOptions{Parents: true}); e != nil {
			return summary, Categorize(e)
		}
	}
	options := []silo.UploadOption{}
	if q.Mode != nil {
		options = append(options, silo.WithFileMode(*q.Mode))
	}
	if q.UID != nil {
		options = append(options, silo.WithFileOwner(*q.UID, q.GID))
	}
	if source == nil {
		source = strings.NewReader("")
	}
	if input, ok := source.(interface {
		ReadContext(context.Context, []byte) (int, error)
	}); ok {
		source = fileContextReader{ctx: ctx, reader: input}
	}
	limit := int64(math.MaxInt64 - 1)
	if uint64(s.Config.FileTransferLimit) < uint64(limit) {
		limit = int64(s.Config.FileTransferLimit)
	}
	bounded := &transferReader{source: io.LimitReader(source, limit+1), remaining: limit}
	hash := sha256.New()
	result, e := m.UploadFile(ctx, q.Path, io.TeeReader(bounded, hash), options...)
	if bounded.exceeded {
		return summary, failure("limit", "upload exceeds the operator file transfer limit", 6)
	}
	if e != nil {
		return summary, Categorize(e)
	}
	return CopySummary{Bytes: result.Bytes, SHA256: hex.EncodeToString(hash.Sum(nil)), Disposition: string(result.Disposition)}, nil
}
func (s *Service) CopyFromVM(parent context.Context, c Caller, q CopyRequest, sink io.Writer) (summary CopySummary, err error) {
	m, id, e := s.copyMachine(parent, c, q)
	if e != nil {
		return summary, e
	}
	defer s.Runtime.CloseMachine(m)
	ctx, cancel, recheck := s.streamContext(parent, c, id, identity.Files)
	defer cancel()
	defer func() {
		if denied := recheck(); denied != nil {
			err = denied
		}
	}()
	entry, e := m.StatFile(ctx, q.Path)
	if e != nil {
		return summary, Categorize(e)
	}
	if entry.Kind != silo.FileEntryFile {
		return summary, failure("usage", fmt.Sprintf("%s:%s is a directory; use: exec %s -- tar -cC DIR . > bundle.tar", q.VM, q.Path, q.VM), 2)
	}
	source, e := m.DownloadFile(ctx, q.Path)
	if e != nil {
		return summary, Categorize(e)
	}
	defer source.Close()
	if sink == nil {
		sink = io.Discard
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			written, writeErr := WriteContext(ctx, sink, buffer[:n])
			if written > 0 {
				_, _ = hash.Write(buffer[:written])
				summary.Bytes += int64(written)
			}
			if writeErr != nil {
				return summary, writeErr
			}
			if written != n {
				return summary, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return summary, Categorize(readErr)
		}
	}
	summary.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return summary, nil
}
