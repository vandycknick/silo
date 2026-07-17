package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	feedRefreshInterval = 15 * time.Minute
	feedRetryInterval   = time.Minute
	maxFeedBytes        = 64 << 20
)

type Facts struct {
	Ecosystem            string
	Operation            string
	Name                 string
	Version              string
	IdentityKnown        bool
	AgeKnown             bool
	AgeHours             int64
	AgeSource            string
	MalwareDataAvailable bool
	Malware              bool
	MalwareReason        string
}

type malwareEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
}

type releaseEntry struct {
	Source      string `json:"source"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	ReleasedOn  int64  `json:"released_on"`
}

type feedState struct {
	malware        map[string]malwareEntry
	releases       map[string]time.Time
	malwareLoaded  bool
	releasesLoaded bool
	lastAttempt    time.Time
	lastSuccess    time.Time
}

type Intelligence struct {
	feedBaseURL  *url.URL
	client       *http.Client
	repositories *Catalog
	now          func() time.Time

	refreshMu sync.Mutex
	mu        sync.RWMutex
	feeds     map[Ecosystem]feedState
}

func NewIntelligence(malwareFeed string, client *http.Client, repositories *Catalog) (*Intelligence, error) {
	parsed, err := url.Parse(malwareFeed)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "0" {
		return nil, fmt.Errorf("malware feed must use HTTPS")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if repositories == nil {
		return nil, fmt.Errorf("intelligence requires configured package repositories")
	}
	clientCopy := *client
	previousRedirectCheck := client.CheckRedirect
	clientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != parsed.Scheme || !strings.EqualFold(request.URL.Host, parsed.Host) {
			return fmt.Errorf("intelligence redirect leaves approved origin")
		}
		if previousRedirectCheck != nil {
			return previousRedirectCheck(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 intelligence redirects")
		}
		return nil
	}
	return &Intelligence{
		feedBaseURL:  parsed,
		client:       &clientCopy,
		repositories: repositories,
		now:          time.Now,
		feeds:        make(map[Ecosystem]feedState),
	}, nil
}

func (i *Intelligence) Refresh(ctx context.Context, ecosystem Ecosystem) error {
	repository, ok := i.repositories.RepositoryForEcosystem(ecosystem)
	if !ok {
		return fmt.Errorf("unsupported package ecosystem %q", ecosystem)
	}
	i.refreshMu.Lock()
	defer i.refreshMu.Unlock()

	now := i.now()
	i.mu.RLock()
	state := i.feeds[ecosystem]
	i.mu.RUnlock()
	retryAfter := feedRefreshInterval
	if state.lastSuccess.IsZero() {
		retryAfter = feedRetryInterval
	}
	if !state.lastAttempt.IsZero() && now.Sub(state.lastAttempt) < retryAfter {
		return nil
	}

	type malwareResult struct {
		entries map[string]malwareEntry
		err     error
	}
	type releaseResult struct {
		entries map[string]time.Time
		err     error
	}
	malwareResults := make(chan malwareResult, 1)
	releaseResults := make(chan releaseResult, 1)
	go func() {
		entries, err := i.fetchMalware(ctx, repository)
		malwareResults <- malwareResult{entries: entries, err: err}
	}()
	go func() {
		entries, err := i.fetchReleases(ctx, repository)
		releaseResults <- releaseResult{entries: entries, err: err}
	}()
	malwareResultValue := <-malwareResults
	releaseResultValue := <-releaseResults
	malware, malwareErr := malwareResultValue.entries, malwareResultValue.err
	releases, releasesErr := releaseResultValue.entries, releaseResultValue.err
	i.mu.Lock()
	state = i.feeds[ecosystem]
	state.lastAttempt = now
	if malwareErr == nil {
		state.malware = malware
		state.malwareLoaded = true
	}
	if releasesErr == nil {
		state.releases = releases
		state.releasesLoaded = true
	}
	if malwareErr == nil && releasesErr == nil {
		state.lastSuccess = now
	}
	i.feeds[ecosystem] = state
	i.mu.Unlock()
	return errors.Join(malwareErr, releasesErr)
}

func (i *Intelligence) Facts(ctx context.Context, ecosystem Ecosystem, operation string, name string, version string, registryReleased *time.Time) Facts {
	repository, ok := i.repositories.RepositoryForEcosystem(ecosystem)
	if !ok {
		return Facts{Ecosystem: string(ecosystem), Operation: operation, Name: name, Version: version}
	}
	_ = i.Refresh(ctx, ecosystem)
	name = repository.NormalizeName(name)
	facts := Facts{
		Ecosystem:     string(ecosystem),
		Operation:     operation,
		Name:          name,
		Version:       version,
		IdentityKnown: name != "" && version != "",
	}

	now := i.now()
	key := packageKey(repository, name, version)
	i.mu.Lock()
	state := i.feeds[ecosystem]
	facts.MalwareDataAvailable = state.malwareLoaded
	if facts.IdentityKnown && registryReleased != nil && !registryReleased.IsZero() {
		setAge(&facts, now, *registryReleased, "registry")
	} else if released, ok := state.releases[key]; facts.IdentityKnown && state.releasesLoaded && ok {
		setAge(&facts, now, released, "feed")
	}
	if facts.IdentityKnown && state.malwareLoaded {
		entry, ok := state.malware[key]
		if !ok {
			entry, ok = state.malware[packageKey(repository, name, "*")]
		}
		if ok {
			facts.MalwareReason = entry.Reason
			facts.Malware = strings.EqualFold(entry.Reason, "MALWARE")
		}
	}
	i.mu.Unlock()
	return facts
}

func (i *Intelligence) fetchMalware(ctx context.Context, repository Repository) (map[string]malwareEntry, error) {
	ecosystem := repository.Ecosystem()
	var entries []malwareEntry
	if err := i.fetchJSON(ctx, repository.FeedPaths().Malware, &entries); err != nil {
		return nil, fmt.Errorf("fetch %s malware feed: %w", ecosystem, err)
	}
	indexed := make(map[string]malwareEntry, len(entries))
	for _, entry := range entries {
		if entry.PackageName == "" || entry.Version == "" || entry.Reason == "" {
			return nil, fmt.Errorf("%s malware feed contains an incomplete entry", ecosystem)
		}
		entry.PackageName = repository.NormalizeName(entry.PackageName)
		indexed[packageKey(repository, entry.PackageName, entry.Version)] = entry
	}
	return indexed, nil
}

func (i *Intelligence) fetchReleases(ctx context.Context, repository Repository) (map[string]time.Time, error) {
	ecosystem := repository.Ecosystem()
	var entries []releaseEntry
	if err := i.fetchJSON(ctx, repository.FeedPaths().Release, &entries); err != nil {
		return nil, fmt.Errorf("fetch %s release feed: %w", ecosystem, err)
	}
	indexed := make(map[string]time.Time, len(entries))
	for _, entry := range entries {
		if entry.Source != "" && !strings.EqualFold(entry.Source, string(ecosystem)) {
			continue
		}
		if entry.PackageName == "" || entry.Version == "" || entry.ReleasedOn <= 0 {
			return nil, fmt.Errorf("%s release feed contains an incomplete entry", ecosystem)
		}
		name := repository.NormalizeName(entry.PackageName)
		indexed[packageKey(repository, name, entry.Version)] = time.Unix(entry.ReleasedOn, 0)
	}
	return indexed, nil
}

func (i *Intelligence) fetchJSON(ctx context.Context, path string, destination any) error {
	endpoint := *i.feedBaseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := i.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxFeedBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("feed must contain exactly one JSON document")
	}
	return nil
}

func setAge(facts *Facts, now time.Time, released time.Time, source string) {
	age := now.Sub(released)
	if age < 0 {
		age = 0
	}
	facts.AgeKnown = true
	facts.AgeHours = int64(age / time.Hour)
	facts.AgeSource = source
}

func packageKey(repository Repository, name string, version string) string {
	return string(repository.Ecosystem()) + "\x00" + repository.NormalizeName(name) + "\x00" + version
}
