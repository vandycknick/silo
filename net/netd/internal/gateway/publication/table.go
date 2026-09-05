package publication

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

var (
	ErrConflict = errors.New("publication conflicts with an existing listener")
	ErrNotFound = errors.New("publication not found")
	ErrClosed   = errors.New("publication table is closed")
)

type Scope string

const AttachmentScope Scope = "attachment"

func SessionScope(id string) Scope {
	return Scope("session:" + id)
}

func (s Scope) AuditName() string {
	if strings.HasPrefix(string(s), "session:") {
		return "session"
	}
	return string(s)
}

type Entry struct {
	Local    string                  `json:"local"`
	Remote   string                  `json:"remote"`
	Protocol types.TransportProtocol `json:"protocol"`
	Scope    Scope                   `json:"-"`
}

type Forwarder interface {
	Expose(protocol types.TransportProtocol, local, remote string) error
	Unexpose(protocol types.TransportProtocol, local string) error
}

type Table struct {
	mu        sync.Mutex
	forwarder Forwarder
	entries   map[string]Entry
	closed    bool
}

func NewTable(forwarder Forwarder) *Table {
	return &Table{forwarder: forwarder, entries: make(map[string]Entry)}
}

func (t *Table) Expose(request types.ExposeRequest, scope Scope) (Entry, bool, error) {
	if t == nil || t.forwarder == nil {
		return Entry{}, false, errors.New("publication forwarder is not configured")
	}
	entry := Entry{Local: request.Local, Remote: request.Remote, Protocol: request.Protocol, Scope: scope}
	key := publicationKey(request.Protocol, request.Local)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return Entry{}, false, ErrClosed
	}
	if existing, ok := t.entries[key]; ok {
		if existing == entry {
			return existing, false, nil
		}
		return Entry{}, false, fmt.Errorf("%w: %s is already published", ErrConflict, request.Local)
	}
	if err := t.forwarder.Expose(request.Protocol, request.Local, request.Remote); err != nil {
		return Entry{}, false, err
	}
	t.entries[key] = entry
	return entry, true, nil
}

func (t *Table) Unexpose(request types.UnexposeRequest) (Entry, error) {
	if t == nil || t.forwarder == nil {
		return Entry{}, errors.New("publication forwarder is not configured")
	}
	key := publicationKey(request.Protocol, request.Local)
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if !ok || entry.Scope != AttachmentScope {
		return Entry{}, ErrNotFound
	}
	delete(t.entries, key)
	return entry, t.forwarder.Unexpose(request.Protocol, request.Local)
}

func (t *Table) All() []Entry {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := make([]Entry, 0, len(t.entries))
	for _, entry := range t.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Local == entries[j].Local {
			return entries[i].Protocol < entries[j].Protocol
		}
		return entries[i].Local < entries[j].Local
	})
	return entries
}

func (t *Table) ReleaseScope(scope Scope) ([]Entry, error) {
	if t == nil || t.forwarder == nil {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var released []Entry
	var releaseErr error
	for key, entry := range t.entries {
		if entry.Scope != scope {
			continue
		}
		err := t.forwarder.Unexpose(entry.Protocol, entry.Local)
		delete(t.entries, key)
		released = append(released, entry)
		if err != nil {
			releaseErr = errors.Join(releaseErr, err)
		}
	}
	return released, releaseErr
}

func (t *Table) Close() error {
	if t == nil || t.forwarder == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var closeErr error
	for key, entry := range t.entries {
		err := t.forwarder.Unexpose(entry.Protocol, entry.Local)
		delete(t.entries, key)
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}

func publicationKey(protocol types.TransportProtocol, local string) string {
	return string(protocol) + "/" + local
}
