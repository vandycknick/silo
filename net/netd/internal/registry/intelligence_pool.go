package registry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const intelligencePollInterval = time.Minute

type pooledIntelligence struct {
	intelligence *Intelligence
	ecosystems   []Ecosystem
}

// IntelligencePool shares last-successful feed snapshots across VM sessions.
// Endpoint policy and learned artifact identities remain session-scoped.
type IntelligencePool struct {
	client *http.Client

	mu      sync.RWMutex
	entries map[string]pooledIntelligence
}

func NewIntelligencePool(client *http.Client) *IntelligencePool {
	return &IntelligencePool{client: client, entries: make(map[string]pooledIntelligence)}
}

func (p *IntelligencePool) Get(malwareFeed string, repositories *Catalog) (*Intelligence, error) {
	if p == nil {
		return NewIntelligence(malwareFeed, nil, repositories)
	}
	candidate, err := NewIntelligence(malwareFeed, p.client, repositories)
	if err != nil {
		return nil, err
	}
	key := candidate.feedBaseURL.String() + "\x00" + repositories.cacheKey()
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.entries[key]; ok {
		return existing.intelligence, nil
	}
	p.entries[key] = pooledIntelligence{intelligence: candidate, ecosystems: repositories.Ecosystems()}
	return candidate, nil
}

func (p *IntelligencePool) Refresh(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	entries := make([]pooledIntelligence, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.mu.RUnlock()
	var refreshErr error
	for _, entry := range entries {
		for _, ecosystem := range entry.ecosystems {
			if err := entry.intelligence.Refresh(ctx, ecosystem); err != nil {
				refreshErr = errors.Join(refreshErr, err)
			}
		}
	}
	return refreshErr
}

func (p *IntelligencePool) Run(ctx context.Context) error {
	if p == nil {
		return nil
	}
	refresh := func() {
		if err := p.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("package intelligence refresh failed; retaining stale data", "error", err)
		}
	}
	refresh()
	ticker := time.NewTicker(intelligencePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refresh()
		}
	}
}
