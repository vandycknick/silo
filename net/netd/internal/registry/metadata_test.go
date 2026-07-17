package registry

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestFilterNPMMetadataRemovesYoungVersionsAndTags(t *testing.T) {
	body := []byte(`{
  "name":"example",
  "dist-tags":{"latest":"2.0.0","stable":"1.0.0"},
  "time":{"1.0.0":"2020-01-01T00:00:00Z","2.0.0":"2026-07-15T11:00:00Z"},
  "versions":{
    "1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}},
    "2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-2.0.0.tgz"}}
  }
}`)
	artifacts := NewArtifactIndex()
	result, err := npmRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/json",
		Request:          Request{Ecosystem: EcosystemNPM, Name: "example"},
		FilterPackageAge: 24,
		Age:              ageVersions("2.0.0"),
		Artifacts:        artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Versions map[string]json.RawMessage `json:"versions"`
		DistTags map[string]string          `json:"dist-tags"`
		Time     map[string]string          `json:"time"`
	}
	if err := json.Unmarshal(result.Body, &filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Versions) != 1 || filtered.Versions["1.0.0"] == nil || filtered.DistTags["latest"] != "1.0.0" || filtered.DistTags["stable"] != "1.0.0" || filtered.Time["2.0.0"] != "" {
		t.Fatalf("filtered metadata = %s", result.Body)
	}
	denied, ok := artifacts.Lookup("registry.npmjs.org", "/example/-/example-2.0.0.tgz")
	if !ok || denied.Version != "2.0.0" || denied.Operation != "download" || denied.RegistryReleased == nil {
		t.Fatalf("denied artifact cache = %#v, %v", denied, ok)
	}
	if result.Suppressed != 1 {
		t.Fatalf("suppressed versions = %d", result.Suppressed)
	}
}

func TestFilterNPMMetadataReturnsEmptySuccessWhenAllVersionsAreYoung(t *testing.T) {
	body := []byte(`{
  "name":"example",
  "dist-tags":{"latest":"1.0.0"},
  "time":{"1.0.0":"2026-07-15T11:00:00Z"},
  "versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}}}
}`)
	result, err := npmRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/json",
		Request:          Request{Ecosystem: EcosystemNPM, Name: "example"},
		FilterPackageAge: 24,
		Age:              ageVersions("1.0.0"),
		Artifacts:        NewArtifactIndex(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Versions map[string]json.RawMessage `json:"versions"`
		DistTags map[string]string          `json:"dist-tags"`
	}
	if err := json.Unmarshal(result.Body, &filtered); err != nil {
		t.Fatal(err)
	}
	if !result.Modified || result.Suppressed != 1 || len(filtered.Versions) != 0 || len(filtered.DistTags) != 0 {
		t.Fatalf("all-young metadata = %#v, %s", result, result.Body)
	}
}

func TestFilterNPMExactManifestPassesThrough(t *testing.T) {
	body := []byte(`{"name":"example","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}}`)
	result, err := npmRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/json",
		Request:          Request{Ecosystem: EcosystemNPM, Name: "example"},
		FilterPackageAge: 24,
		Age: func(Candidate) (int64, bool) {
			t.Fatal("exact manifest must not perform candidate age evaluation")
			return 0, false
		},
		Artifacts: NewArtifactIndex(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Modified || string(result.Body) != string(body) {
		t.Fatalf("exact manifest changed: %#v", result)
	}
}

func TestFilterPyPISimpleJSONRemovesYoungArtifactsAndVersions(t *testing.T) {
	body := []byte(`{
  "name":"example",
  "versions":["1.0.0","2.0.0"],
  "files":[
    {"filename":"example-1.0.0.tar.gz","url":"https://files.pythonhosted.org/packages/example-1.0.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"},
    {"filename":"example-2.0.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/example-2.0.0-py3-none-any.whl","upload-time":"2026-07-15T11:00:00Z"}
  ]
	}`)
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := NewArtifactIndex()
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/vnd.pypi.simple.v1+json",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age:              ageVersions("2.0.0"),
		Artifacts:        artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Files    []map[string]json.RawMessage `json:"files"`
		Versions []string                     `json:"versions"`
	}
	if err := json.Unmarshal(result.Body, &filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Files) != 1 || len(filtered.Versions) != 1 || filtered.Versions[0] != "1.0.0" {
		t.Fatalf("filtered metadata = %s", result.Body)
	}
}

func TestFilterPyPISimpleJSONCountsOneSuppressedRelease(t *testing.T) {
	body := []byte(`{
  "name":"example",
  "versions":["1.0.0"],
  "files":[
    {"filename":"example-1.0.0.tar.gz","url":"example-1.0.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"},
    {"filename":"example-1.0.0-py3-none-any.whl","url":"example-1.0.0-py3-none-any.whl","upload-time":"2020-01-01T01:00:00Z"}
  ]
}`)
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/vnd.pypi.simple.v1+json",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age: func(candidate Candidate) (int64, bool) {
			if candidate.RegistryReleased == nil {
				t.Fatalf("PyPI candidate omitted registry upload time: %#v", candidate)
			}
			return 1, true
		},
		Artifacts: NewArtifactIndex(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Suppressed != 1 {
		t.Fatalf("suppressed releases = %#v", result)
	}
}

func TestFilterPyPISimpleJSONIndexesRelativeArtifactURLs(t *testing.T) {
	body := []byte(`{
  "name":"example",
  "versions":["1.0.0"],
  "files":[
    {"filename":"example-1.0.0.tar.gz","url":"../../packages/example-1.0.0.tar.gz#sha256=abc","upload-time":"2020-01-01T00:00:00Z","core-metadata":{"sha256":"def"}},
	{"filename":"example-1.0.0-py3-none-any.whl","url":"../../packages/example-1.0.0-py3-none-any.whl","upload-time":"2020-01-01T01:00:00Z","dist-info-metadata":true},
	{"filename":"example-1.0.0.zip","url":"../../packages/example-1.0.0.zip","upload-time":"2020-01-01T02:00:00Z"}
  ]
}`)
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := NewArtifactIndex()
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/vnd.pypi.simple.v1+json",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age:              oldPackage,
		Artifacts:        artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Suppressed != 0 {
		t.Fatalf("filter result = %#v", result)
	}
	artifact, ok := artifacts.Lookup("pypi.org", "/packages/example-1.0.0.tar.gz")
	if !ok || artifact.Name != "example" || artifact.Version != "1.0.0" || artifact.Operation != "download" {
		t.Fatalf("relative artifact cache = %#v, %v", artifact, ok)
	}
	for _, artifactPath := range []string{
		"/packages/example-1.0.0.tar.gz.metadata",
		"/packages/example-1.0.0-py3-none-any.whl.metadata",
	} {
		metadata, ok := artifacts.Lookup("pypi.org", artifactPath)
		if !ok || metadata.Name != "example" || metadata.Version != "1.0.0" {
			t.Fatalf("core metadata cache for %q = %#v, %v", artifactPath, metadata, ok)
		}
	}
	if _, ok := artifacts.Lookup("pypi.org", "/packages/example-1.0.0.zip.metadata"); ok {
		t.Fatal("unadvertised core metadata path was indexed")
	}
}

func TestFilterPyPISimpleHTMLRemovesYoungLinks(t *testing.T) {
	body := []byte(`<!doctype html><html><body>
<a href="https://files.pythonhosted.org/packages/example-1.0.0.tar.gz" data-upload-time="2020-01-01T00:00:00Z" data-core-metadata="sha256=abc">example-1.0.0.tar.gz</a>
<a href="https://files.pythonhosted.org/packages/example-2.0.0-py3-none-any.whl" data-upload-time="2026-07-15T11:00:00Z" data-dist-info-metadata="true">example-2.0.0-py3-none-any.whl</a>
</body></html>`)
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := NewArtifactIndex()
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/vnd.pypi.simple.v1+html",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age:              ageVersions("2.0.0"),
		Artifacts:        artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(result.Body)
	if !strings.Contains(text, "example-1.0.0.tar.gz") || strings.Contains(text, "example-2.0.0") {
		t.Fatalf("filtered HTML = %s", text)
	}
	for _, artifactPath := range []string{
		"/packages/example-1.0.0.tar.gz.metadata",
		"/packages/example-2.0.0-py3-none-any.whl.metadata",
	} {
		if _, ok := artifacts.Lookup("files.pythonhosted.org", artifactPath); !ok {
			t.Fatalf("core metadata path %q was not indexed", artifactPath)
		}
	}
}

func TestFilterPyPISimpleHTMLKeepsUnrecognizedLinks(t *testing.T) {
	body := []byte(`<!doctype html><html><body>
<a href="https://pypi.org/project/example/">project page</a>
<a href="https://files.pythonhosted.org/packages/example-1.0.0.tar.gz">example-1.0.0.tar.gz</a>
</body></html>`)
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "text/html",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age:              oldPackage,
		Artifacts:        NewArtifactIndex(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Modified || string(result.Body) != string(body) {
		t.Fatalf("unrecognized link changed metadata: %s", result.Body)
	}
}

func TestFilterPyPIProjectJSONRemovesYoungReleasesAndURLs(t *testing.T) {
	body := []byte(`{
	"info":{"name":"example","version":"2.0.0","release_url":"https://pypi.org/project/example/2.0.0/","requires_dist":["denied-dependency"],"requires_python":">=3.13"},
  "releases":{
    "1.0.0":[{"filename":"example-1.0.0.tar.gz","url":"https://files.pythonhosted.org/packages/example-1.0.0.tar.gz","upload_time_iso_8601":"2020-01-01T00:00:00Z"}],
	"2.0.0":[{"filename":"example-2.0.0.tar.gz","url":"https://files.pythonhosted.org/packages/example-2.0.0.tar.gz","upload_time_iso_8601":"2026-07-15T11:00:00Z","core-metadata":true}]
  },
	"urls":[{"filename":"example-2.0.0.tar.gz","url":"https://files.pythonhosted.org/packages/example-2.0.0.tar.gz","upload_time_iso_8601":"2026-07-15T11:00:00Z","core-metadata":true}],
	"vulnerabilities":[{"id":"PYSEC-DENIED"}]
}`)
	baseURL, err := url.Parse("https://pypi.org/pypi/example/json")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := NewArtifactIndex()
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/json",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age: func(candidate Candidate) (int64, bool) {
			if candidate.RegistryReleased == nil {
				t.Fatalf("project release %q omitted upload timestamp", candidate.Version)
			}
			if candidate.Version == "2.0.0" {
				return 1, true
			}
			return 100, true
		},
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Releases map[string][]json.RawMessage `json:"releases"`
		URLs     []json.RawMessage            `json:"urls"`
		Info     map[string]json.RawMessage   `json:"info"`
		Vulns    []json.RawMessage            `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(result.Body, &filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Releases) != 1 || filtered.Releases["1.0.0"] == nil || len(filtered.URLs) != 0 || len(filtered.Vulns) != 0 {
		t.Fatalf("filtered project metadata = %s", result.Body)
	}
	if jsonString(filtered.Info["name"]) != "example" || len(filtered.Info) != 1 {
		t.Fatalf("filtered project info = %s", result.Body)
	}
	metadata, ok := artifacts.Lookup("files.pythonhosted.org", "/packages/example-2.0.0.tar.gz.metadata")
	if !ok || metadata.Version != "2.0.0" {
		t.Fatalf("project core metadata cache = %#v, %v", metadata, ok)
	}
}

func TestFilterPyPIProjectJSONUsesEarliestReleaseFileTimestamp(t *testing.T) {
	body := []byte(`{
  "info":{"name":"example","version":"1.0.0"},
  "releases":{"1.0.0":[
    {"filename":"example-1.0.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/example-1.0.0-py3-none-any.whl","upload_time_iso_8601":"2026-07-15T11:00:00Z"},
    {"filename":"example-1.0.0.tar.gz","url":"https://files.pythonhosted.org/packages/example-1.0.0.tar.gz","upload_time_iso_8601":"2020-01-01T00:00:00Z"}
  ]}
}`)
	baseURL, err := url.Parse("https://pypi.org/pypi/example/json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pypiRepository{}.filterMetadata(MetadataInput{
		Body:             body,
		ContentType:      "application/json",
		URL:              baseURL,
		Request:          Request{Ecosystem: EcosystemPyPI, Name: "example"},
		FilterPackageAge: 24,
		Age: func(candidate Candidate) (int64, bool) {
			if candidate.RegistryReleased == nil || candidate.RegistryReleased.Year() != 2020 {
				t.Fatalf("release candidate timestamp = %v", candidate.RegistryReleased)
			}
			return 100, true
		},
		Artifacts: NewArtifactIndex(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Modified || result.Suppressed != 0 || string(result.Body) != string(body) {
		t.Fatalf("old release was filtered: %#v", result)
	}
}

func TestPyPIFilenameVersion(t *testing.T) {
	tests := map[string]string{
		"foo_bar-1.2.3-py3-none-any.whl": "1.2.3",
		"foo-bar-1.2.3.tar.gz":           "1.2.3",
		"foo_bar-2.0.zip":                "2.0",
	}
	for filename, expected := range tests {
		if version := pypiFilenameVersion("foo-bar", filename); version != expected {
			t.Errorf("pypiFilenameVersion(%q) = %q, want %q", filename, version, expected)
		}
	}
}

func ageVersions(young ...string) AgeLookup {
	return func(candidate Candidate) (int64, bool) {
		for _, version := range young {
			if candidate.Version == version {
				return 1, true
			}
		}
		return 100, true
	}
}

func oldPackage(Candidate) (int64, bool) {
	return 100, true
}
