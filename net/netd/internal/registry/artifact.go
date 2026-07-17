package registry

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxObservedArtifacts = 100_000

type Candidate struct {
	Ecosystem        Ecosystem
	Operation        string
	Name             string
	Version          string
	RegistryReleased *time.Time
}

func (c Candidate) Key() string {
	return string(c.Ecosystem) + "\x00" + c.Operation + "\x00" + c.Name + "\x00" + c.Version
}

type AgeLookup func(Candidate) (int64, bool)

type MetadataInput struct {
	Body             []byte
	ContentType      string
	URL              *url.URL
	Request          Request
	FilterPackageAge uint32
	Age              AgeLookup
	Artifacts        *ArtifactIndex
}

type FilterResult struct {
	Body       []byte
	Modified   bool
	Suppressed int
}

func (i MetadataInput) tooYoung(candidate Candidate) bool {
	if i.FilterPackageAge == 0 || i.Age == nil {
		return false
	}
	ageHours, known := i.Age(candidate)
	return known && ageHours < int64(i.FilterPackageAge)
}

type ArtifactIndex struct {
	mu      sync.RWMutex
	entries map[string]Candidate
	order   []string
}

func NewArtifactIndex() *ArtifactIndex {
	return &ArtifactIndex{entries: make(map[string]Candidate)}
}

func (i *ArtifactIndex) Observe(rawURL string, candidate Candidate) {
	if i == nil {
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" || parsed.Path == "" {
		return
	}
	i.mu.Lock()
	key := artifactKey(parsed.Hostname(), parsed.Path)
	if _, exists := i.entries[key]; !exists {
		if len(i.order) >= maxObservedArtifacts {
			delete(i.entries, i.order[0])
			i.order = i.order[1:]
		}
		i.order = append(i.order, key)
	}
	i.entries[key] = candidate
	i.mu.Unlock()
}

func (i *ArtifactIndex) Lookup(host string, requestPath string) (Candidate, bool) {
	if i == nil {
		return Candidate{}, false
	}
	i.mu.RLock()
	candidate, ok := i.entries[artifactKey(host, requestPath)]
	i.mu.RUnlock()
	return candidate, ok
}

func artifactKey(host string, requestPath string) string {
	return strings.ToLower(strings.TrimSuffix(host, ".")) + "\x00" + requestPath
}
