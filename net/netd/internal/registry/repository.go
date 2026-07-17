package registry

import (
	"fmt"
	"mime"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

type RequestKind string

const (
	RequestUnknown  RequestKind = "unknown"
	RequestMetadata RequestKind = "metadata"
	RequestArtifact RequestKind = "artifact"
)

type Request struct {
	Kind             RequestKind
	Ecosystem        Ecosystem
	Operation        string
	Name             string
	Version          string
	RegistryReleased *time.Time
}

type FeedPaths struct {
	Malware string
	Release string
}

type repositoryAdapter interface {
	ecosystem() Ecosystem
	hosts() []string
	normalizeName(string) string
	classify(string, string, string) Request
	prepareMetadataRequest(http.Header)
	filterMetadata(MetadataInput) (FilterResult, error)
	feedPaths() FeedPaths
}

// Repository is the concrete facade for one supported package repository.
type Repository struct {
	adapter repositoryAdapter
}

func (r Repository) Ecosystem() Ecosystem {
	return r.adapter.ecosystem()
}

func (r Repository) Hosts() []string {
	return append([]string(nil), r.adapter.hosts()...)
}

func (r Repository) NormalizeName(name string) string {
	return r.adapter.normalizeName(name)
}

func (r Repository) Classify(method string, host string, requestPath string) Request {
	return r.adapter.classify(method, host, requestPath)
}

func (r Repository) PrepareMetadataRequest(header http.Header) {
	r.adapter.prepareMetadataRequest(header)
}

func (r Repository) FilterMetadata(input MetadataInput) (FilterResult, error) {
	return r.adapter.filterMetadata(input)
}

func (r Repository) FeedPaths() FeedPaths {
	return r.adapter.feedPaths()
}

type Catalog struct {
	byEcosystem map[Ecosystem]Repository
	byHost      map[string]Repository
}

func NewCatalog(names []string) (*Catalog, error) {
	catalog := &Catalog{
		byEcosystem: make(map[Ecosystem]Repository, len(names)),
		byHost:      make(map[string]Repository),
	}
	for _, name := range names {
		repository, ok := repositoryByName(name)
		if !ok {
			return nil, fmt.Errorf("unsupported package repository %q", name)
		}
		if _, exists := catalog.byEcosystem[repository.Ecosystem()]; exists {
			return nil, fmt.Errorf("package repository %q is configured more than once", name)
		}
		catalog.byEcosystem[repository.Ecosystem()] = repository
		for _, host := range repository.Hosts() {
			catalog.byHost[normalizeHost(host)] = repository
		}
	}
	return catalog, nil
}

func DefaultCatalog() *Catalog {
	catalog, _ := NewCatalog([]string{string(EcosystemNPM), string(EcosystemPyPI)})
	return catalog
}

func (c *Catalog) RepositoryForHost(host string) (Repository, bool) {
	if c == nil {
		return Repository{}, false
	}
	repository, ok := c.byHost[normalizeHost(host)]
	return repository, ok
}

func (c *Catalog) RepositoryForEcosystem(ecosystem Ecosystem) (Repository, bool) {
	if c == nil {
		return Repository{}, false
	}
	repository, ok := c.byEcosystem[ecosystem]
	return repository, ok
}

func (c *Catalog) Ecosystems() []Ecosystem {
	if c == nil {
		return nil
	}
	ecosystems := make([]Ecosystem, 0, len(c.byEcosystem))
	for ecosystem := range c.byEcosystem {
		ecosystems = append(ecosystems, ecosystem)
	}
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })
	return ecosystems
}

func (c *Catalog) cacheKey() string {
	ecosystems := c.Ecosystems()
	parts := make([]string, len(ecosystems))
	for index, ecosystem := range ecosystems {
		parts[index] = string(ecosystem)
	}
	return strings.Join(parts, ",")
}

func HostsForNames(names []string) ([]string, error) {
	_, err := NewCatalog(names)
	if err != nil {
		return nil, err
	}
	var hosts []string
	seen := make(map[string]struct{})
	for _, name := range names {
		repository, _ := repositoryByName(name)
		for _, host := range repository.Hosts() {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func ClassifyRequest(method string, host string, requestPath string) Request {
	repository, ok := DefaultCatalog().RepositoryForHost(host)
	if !ok {
		return Request{Kind: RequestUnknown}
	}
	return repository.Classify(method, host, requestPath)
}

func repositoryByName(name string) (Repository, bool) {
	switch name {
	case string(EcosystemNPM):
		return Repository{adapter: npmRepository{}}, true
	case string(EcosystemPyPI):
		return Repository{adapter: pypiRepository{}}, true
	default:
		return Repository{}, false
	}
}

func requestOperation(method string) string {
	if method == http.MethodGet || method == http.MethodHead {
		return "resolve"
	}
	return "publish"
}

func splitPath(value string) []string {
	value = strings.Trim(path.Clean("/"+value), "/")
	if value == "" || value == "." {
		return nil
	}
	return strings.Split(value, "/")
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func mediaType(contentType string) (string, error) {
	parsed, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	return strings.ToLower(parsed), nil
}

func isJSONMediaType(value string) bool {
	return value == "application/json" || strings.HasSuffix(value, "+json")
}
