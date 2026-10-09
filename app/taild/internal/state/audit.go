package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

type Decision struct {
	Time       time.Time            `json:"time"`
	Principals []identity.Principal `json:"principals"`
	NodeID     string               `json:"node_id"`
	Action     string               `json:"action"`
	Allowed    bool                 `json:"allowed"`
	Code       string               `json:"code,omitempty"`
}
type Audit struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	limit   int64
	backups int
}

func OpenAudit(home string, limit int64, backups int) (*Audit, error) {
	if limit < 1 || backups < 1 {
		return nil, errors.New("invalid audit rotation limits")
	}
	dir := filepath.Join(home, "logs", "taild")
	if e := PrivateDir(dir); e != nil {
		return nil, e
	}
	a := &Audit{path: filepath.Join(dir, "audit.jsonl"), limit: limit, backups: backups}
	return a, a.open()
}
func (a *Audit) open() error {
	if info, e := os.Lstat(a.path); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("audit must be a private regular file")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	a.file = f
	a.size = info.Size()
	return nil
}
func (a *Audit) Append(d Decision) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return errors.New("audit closed")
	}
	d.Time = time.Now().UTC()
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if a.size > 0 && a.size+int64(len(b)) > a.limit {
		if e = a.file.Sync(); e != nil {
			return e
		}
		if e = a.file.Close(); e != nil {
			return e
		}
		a.file = nil
		for i := a.backups; i > 1; i-- {
			e = os.Rename(fmt.Sprintf("%s.%d", a.path, i-1), fmt.Sprintf("%s.%d", a.path, i))
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		if e = os.Rename(a.path, a.path+".1"); e != nil {
			return e
		}
		if e = a.open(); e != nil {
			return e
		}
		if e = SyncDir(filepath.Dir(a.path)); e != nil {
			return e
		}
	}
	n, e := a.file.Write(b)
	a.size += int64(n)
	if e != nil {
		return e
	}
	return a.file.Sync()
}
func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	e := a.file.Close()
	a.file = nil
	return e
}
