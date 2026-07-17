package registry

import (
	"net/http"
	"testing"
)

func TestClassifyNPMRequests(t *testing.T) {
	tests := []struct {
		path    string
		kind    RequestKind
		name    string
		version string
	}{
		{path: "/lodash", kind: RequestMetadata, name: "lodash"},
		{path: "/lodash/4.17.21", kind: RequestMetadata, name: "lodash"},
		{path: "/lodash/-/lodash-4.17.21.tgz", kind: RequestArtifact, name: "lodash", version: "4.17.21"},
		{path: "/@scope/pkg", kind: RequestMetadata, name: "@scope/pkg"},
		{path: "/@scope%2Fpkg", kind: RequestMetadata, name: "@scope/pkg"},
		{path: "/@scope/pkg/-/pkg-1.2.3.tgz", kind: RequestArtifact, name: "@scope/pkg", version: "1.2.3"},
		{path: "/-/v1/search", kind: RequestUnknown},
		{path: "/lodash/not-a-tarball.tgz", kind: RequestUnknown},
		{path: "/lodash/-/other-1.0.0.tgz", kind: RequestUnknown},
	}
	for _, test := range tests {
		classified := ClassifyRequest(http.MethodGet, "registry.npmjs.org", test.path)
		if classified.Kind != test.kind || classified.Name != test.name || classified.Version != test.version {
			t.Errorf("ClassifyRequest(%q) = %#v", test.path, classified)
		}
	}
}

func TestClassifyPyPIRequests(t *testing.T) {
	metadata := ClassifyRequest(http.MethodGet, "pypi.org", "/simple/Foo_Bar/")
	if metadata.Kind != RequestMetadata || metadata.Name != "foo-bar" || metadata.Ecosystem != EcosystemPyPI {
		t.Fatalf("metadata request = %#v", metadata)
	}
	release := ClassifyRequest(http.MethodGet, "pypi.org", "/pypi/Foo.Bar/1.2.3/json")
	if release.Kind != RequestMetadata || release.Name != "foo-bar" || release.Version != "" {
		t.Fatalf("release request = %#v", release)
	}
	artifact := ClassifyRequest(http.MethodGet, "files.pythonhosted.org", "/packages/aa/bb/example-1.2.3-py3-none-any.whl")
	if artifact.Kind != RequestArtifact || artifact.Operation != "download" || artifact.Name != "example" || artifact.Version != "1.2.3" {
		t.Fatalf("artifact request = %#v", artifact)
	}
	metadataArtifact := ClassifyRequest(http.MethodGet, "files.pythonhosted.org", "/packages/aa/bb/Foo_Bar-2.0.0-py3-none-any.whl.metadata")
	if metadataArtifact.Kind != RequestArtifact || metadataArtifact.Name != "foo-bar" || metadataArtifact.Version != "2.0.0" {
		t.Fatalf("metadata artifact request = %#v", metadataArtifact)
	}
	latest := ClassifyRequest(http.MethodGet, "files.pythonhosted.org", "/packages/aa/bb/example-latest.tar.gz")
	if latest.Kind != RequestUnknown {
		t.Fatalf("latest artifact request = %#v", latest)
	}
}
