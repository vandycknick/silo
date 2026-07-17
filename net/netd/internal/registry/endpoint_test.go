package registry

import (
	"net/http"
	"net/url"
	"testing"
)

func TestEndpointParsesPyPIArtifactWithoutMetadataObservation(t *testing.T) {
	endpoint := newTestEndpoint(t, "pypi")
	classified := endpoint.Classify(http.MethodGet, "files.pythonhosted.org", "/packages/aa/bb/foo_bar-2.0.0-py3-none-any.whl")
	if classified.Kind != RequestArtifact || classified.Name != "foo-bar" || classified.Version != "2.0.0" {
		t.Fatalf("classified direct artifact = %#v", classified)
	}
}

func TestEndpointUsesAdvertisedPyPICoreMetadataIdentity(t *testing.T) {
	endpoint := newTestEndpoint(t, "pypi")
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = endpoint.FilterMetadata(MetadataInput{
		Body: []byte(`{
  "name":"example",
  "files":[{
    "filename":"example-1.0.0-py3-none-any.whl",
    "url":"https://files.pythonhosted.org/packages/opaque-download",
    "upload-time":"2020-01-01T00:00:00Z",
    "core-metadata":{"sha256":"abc"}
  }]
}`),
		ContentType: "application/vnd.pypi.simple.v1+json",
		URL:         baseURL,
		Request:     Request{Ecosystem: EcosystemPyPI, Name: "example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	classified := endpoint.Classify(http.MethodGet, "files.pythonhosted.org", "/packages/opaque-download.metadata")
	if classified.Kind != RequestArtifact || classified.Name != "example" || classified.Version != "1.0.0" {
		t.Fatalf("core metadata request = %#v", classified)
	}
}

func newTestEndpoint(t *testing.T, repositories ...string) *Endpoint {
	t.Helper()
	endpoint, err := NewEndpoint(EndpointConfig{
		Repositories: repositories,
		MalwareFeed:  "https://intelligence.example.test",
	}, NewIntelligencePool(nil))
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}
