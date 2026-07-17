package registry

import (
	"net/http"
	"slices"
	"testing"
)

func TestRepositoryCatalogScopesHostsAndFeedPaths(t *testing.T) {
	catalog, err := NewCatalog([]string{"npm"})
	if err != nil {
		t.Fatal(err)
	}
	npm, ok := catalog.RepositoryForHost("REGISTRY.NPMJS.ORG.")
	if !ok || npm.Ecosystem() != EcosystemNPM {
		t.Fatalf("npm repository = %#v, %v", npm, ok)
	}
	if _, ok := catalog.RepositoryForHost("pypi.org"); ok {
		t.Fatal("npm-only catalog accepted a PyPI host")
	}
	if feeds := npm.FeedPaths(); feeds.Malware != "malware_predictions.json" || feeds.Release != "releases/npm.json" {
		t.Fatalf("npm feeds = %#v", feeds)
	}

	hosts, err := HostsForNames([]string{"npm", "pypi"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"registry.npmjs.com",
		"pypi.org",
		"files.pythonhosted.org",
		"pypi.python.org",
		"pythonhosted.org",
	}
	if !slices.Equal(hosts, want) {
		t.Fatalf("repository hosts = %#v, want %#v", hosts, want)
	}
}

func TestRepositoryAdaptersOwnRequestClassification(t *testing.T) {
	catalog := DefaultCatalog()
	npm, ok := catalog.RepositoryForEcosystem(EcosystemNPM)
	if !ok {
		t.Fatal("npm repository missing")
	}
	npmRequest := npm.Classify(http.MethodGet, "registry.npmjs.org", "/@scope/pkg/-/pkg-1.2.3.tgz")
	if npmRequest.Kind != RequestArtifact || npmRequest.Name != "@scope/pkg" || npmRequest.Version != "1.2.3" {
		t.Fatalf("npm request = %#v", npmRequest)
	}

	pypi, ok := catalog.RepositoryForEcosystem(EcosystemPyPI)
	if !ok {
		t.Fatal("PyPI repository missing")
	}
	pypiRequest := pypi.Classify(http.MethodGet, "pypi.org", "/simple/Foo_Bar/")
	if pypiRequest.Kind != RequestMetadata || pypiRequest.Name != "foo-bar" {
		t.Fatalf("PyPI request = %#v", pypiRequest)
	}
	if feeds := pypi.FeedPaths(); feeds.Malware != "malware_pypi.json" || feeds.Release != "releases/pypi.json" {
		t.Fatalf("PyPI feeds = %#v", feeds)
	}
}

func TestRepositoryCatalogRejectsUnknownAndDuplicateNames(t *testing.T) {
	if _, err := NewCatalog([]string{"rubygems"}); err == nil {
		t.Fatal("unknown repository was accepted")
	}
	if _, err := NewCatalog([]string{"npm", "npm"}); err == nil {
		t.Fatal("duplicate repository was accepted")
	}
}

func TestRepositoryAdaptersPassThroughUnsupportedMetadataTypes(t *testing.T) {
	catalog := DefaultCatalog()
	for _, ecosystem := range []Ecosystem{EcosystemNPM, EcosystemPyPI} {
		repository, ok := catalog.RepositoryForEcosystem(ecosystem)
		if !ok {
			t.Fatalf("repository %q missing", ecosystem)
		}
		result, err := repository.FilterMetadata(MetadataInput{
			Body:        []byte("not metadata"),
			ContentType: "application/octet-stream",
			Request:     Request{Ecosystem: ecosystem, Name: "example"},
			Artifacts:   NewArtifactIndex(),
		})
		if err != nil || result.Modified || string(result.Body) != "not metadata" {
			t.Fatalf("repository %q pass-through = %#v, %v", ecosystem, result, err)
		}
	}
}

func TestRepositoryAdaptersPassThroughMalformedMetadata(t *testing.T) {
	for _, ecosystem := range []Ecosystem{EcosystemNPM, EcosystemPyPI} {
		repository, ok := DefaultCatalog().RepositoryForEcosystem(ecosystem)
		if !ok {
			t.Fatalf("repository %q missing", ecosystem)
		}
		result, err := repository.FilterMetadata(MetadataInput{
			Body:        []byte("{"),
			ContentType: "application/json",
			Request:     Request{Ecosystem: ecosystem, Name: "example"},
			Artifacts:   NewArtifactIndex(),
		})
		if err != nil || result.Modified || string(result.Body) != "{" {
			t.Fatalf("repository %q malformed pass-through = %#v, %v", ecosystem, result, err)
		}
	}
}

func TestRepositoryAdaptersPrepareMetadataHeaders(t *testing.T) {
	catalog := DefaultCatalog()
	npm, _ := catalog.RepositoryForEcosystem(EcosystemNPM)
	npmHeader := http.Header{
		"Accept":            {"application/vnd.npm.install-v1+json"},
		"If-None-Match":     {`"npm"`},
		"If-Modified-Since": {"yesterday"},
	}
	npm.PrepareMetadataRequest(npmHeader)
	if npmHeader.Get("Accept") != "application/json" || npmHeader.Get("If-None-Match") == "" || npmHeader.Get("If-Modified-Since") == "" {
		t.Fatalf("npm metadata headers = %#v", npmHeader)
	}

	pypi, _ := catalog.RepositoryForEcosystem(EcosystemPyPI)
	pypiHeader := http.Header{
		"Accept":            {"application/vnd.pypi.simple.v1+json"},
		"If-None-Match":     {`"pypi"`},
		"If-Modified-Since": {"yesterday"},
	}
	pypi.PrepareMetadataRequest(pypiHeader)
	if pypiHeader.Get("Accept") == "" || pypiHeader.Get("If-None-Match") != "" || pypiHeader.Get("If-Modified-Since") != "" {
		t.Fatalf("PyPI metadata headers = %#v", pypiHeader)
	}
}
