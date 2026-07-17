package registry

import (
	"fmt"
	"net/http"
	"time"
)

type EndpointConfig struct {
	Repositories           []string
	MalwareFeed            string
	MinimumPackageAgeHours uint32
}

// Endpoint owns package-domain state for one VM policy endpoint.
type Endpoint struct {
	repositories *Catalog
	intelligence *Intelligence
	artifacts    *ArtifactIndex
	minimumAge   uint32
}

func NewEndpoint(config EndpointConfig, intelligencePool *IntelligencePool) (*Endpoint, error) {
	repositories, err := NewCatalog(config.Repositories)
	if err != nil {
		return nil, err
	}
	intelligence, err := intelligencePool.Get(config.MalwareFeed, repositories)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		repositories: repositories,
		intelligence: intelligence,
		artifacts:    NewArtifactIndex(),
		minimumAge:   config.MinimumPackageAgeHours,
	}, nil
}

func (e *Endpoint) Classify(method string, host string, requestPath string) Request {
	if e == nil {
		return Request{Kind: RequestUnknown}
	}
	repository, ok := e.repositories.RepositoryForHost(host)
	if !ok {
		return Request{Kind: RequestUnknown}
	}
	classified := repository.Classify(method, host, requestPath)
	if classified.Kind == RequestMetadata {
		return classified
	}
	observed, ok := e.artifacts.Lookup(host, requestPath)
	if !ok {
		return classified
	}
	return Request{
		Kind: RequestArtifact, Ecosystem: observed.Ecosystem, Operation: observed.Operation,
		Name: observed.Name, Version: observed.Version, RegistryReleased: observed.RegistryReleased,
	}
}

func (e *Endpoint) Facts(candidate Candidate) Facts {
	if e == nil {
		return Facts{
			Ecosystem: string(candidate.Ecosystem), Operation: candidate.Operation,
			Name: candidate.Name, Version: candidate.Version,
		}
	}
	return e.intelligence.Facts(
		candidate.Ecosystem,
		candidate.Operation,
		candidate.Name,
		candidate.Version,
		candidate.RegistryReleased,
	)
}

func (e *Endpoint) PrepareMetadataRequest(ecosystem Ecosystem, header http.Header) error {
	if e == nil {
		return fmt.Errorf("registry endpoint is not configured")
	}
	repository, ok := e.repositories.RepositoryForEcosystem(ecosystem)
	if !ok {
		return fmt.Errorf("package ecosystem %q is not configured", ecosystem)
	}
	repository.PrepareMetadataRequest(header)
	return nil
}

func (e *Endpoint) FilterMetadata(input MetadataInput) (FilterResult, error) {
	if e == nil {
		return FilterResult{}, fmt.Errorf("registry endpoint is not configured")
	}
	repository, ok := e.repositories.RepositoryForEcosystem(input.Request.Ecosystem)
	if !ok {
		return FilterResult{}, fmt.Errorf("package ecosystem %q is not configured", input.Request.Ecosystem)
	}
	input.FilterPackageAge = e.minimumAge
	input.Age = e.packageAge
	input.Artifacts = e.artifacts
	return repository.FilterMetadata(input)
}

func (e *Endpoint) MinimumPackageAgeHours() uint32 {
	if e == nil {
		return 0
	}
	return e.minimumAge
}

func (e *Endpoint) packageAge(candidate Candidate) (int64, bool) {
	if candidate.RegistryReleased != nil {
		elapsed := time.Since(*candidate.RegistryReleased)
		if elapsed < 0 {
			elapsed = 0
		}
		return int64(elapsed / time.Hour), true
	}
	facts := e.Facts(candidate)
	return facts.AgeHours, facts.AgeKnown
}
