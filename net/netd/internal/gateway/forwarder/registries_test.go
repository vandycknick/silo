package forwarder

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	packageregistry "github.com/vandycknick/silo/net/netd/internal/registry"
)

func TestClassifyRegistryRequestUsesObservedArtifactIdentity(t *testing.T) {
	artifacts := packageregistry.NewArtifactIndex()
	artifacts.Observe("https://pypi.org/packages/opaque-download", packageregistry.Candidate{
		Ecosystem: packageregistry.EcosystemPyPI,
		Operation: "download",
		Name:      "example",
		Version:   "1.0.0",
	})
	repositories, err := packageregistry.NewCatalog([]string{"pypi"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &registryEndpointRuntime{repositories: repositories, artifacts: artifacts}

	classified := classifyRegistryRequest(runtime, http.MethodGet, "pypi.org", "/packages/opaque-download")
	if classified.Kind != packageregistry.RequestArtifact || classified.Ecosystem != packageregistry.EcosystemPyPI || classified.Name != "example" || classified.Version != "1.0.0" {
		t.Fatalf("classified request = %#v", classified)
	}
}

func TestPackageAgeInvariantOnlyDeniesKnownYoungArtifacts(t *testing.T) {
	base := hooks.RouteDecision{
		Action: hooks.RouteAllowDirect,
		Package: &hooks.Package{
			Ecosystem:     "npm",
			Operation:     "download",
			Name:          "example",
			Version:       "1.0.0",
			IdentityKnown: true,
		},
	}

	unknown := applyPackageAgeInvariant(base, 24)
	if unknown.Action != hooks.RouteAllowDirect {
		t.Fatalf("unknown age decision = %#v", unknown)
	}

	base.Package.AgeKnown = true
	base.Package.AgeHours = 24
	boundary := applyPackageAgeInvariant(base, 24)
	if boundary.Action != hooks.RouteAllowDirect {
		t.Fatalf("boundary age decision = %#v", boundary)
	}

	base.Package.AgeHours = 23
	young := applyPackageAgeInvariant(base, 24)
	if young.Action != hooks.RouteDeny || young.Source != "endpoint" || young.RuleName != "" || young.Reason != "package was released less than 24 hours ago" {
		t.Fatalf("young artifact decision = %#v", young)
	}
}

func TestClassifyRegistryRequestParsesPyPIArtifactWithoutMetadataObservation(t *testing.T) {
	repositories, err := packageregistry.NewCatalog([]string{"pypi"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &registryEndpointRuntime{repositories: repositories, artifacts: packageregistry.NewArtifactIndex()}

	classified := classifyRegistryRequest(runtime, http.MethodGet, "files.pythonhosted.org", "/packages/aa/bb/foo_bar-2.0.0-py3-none-any.whl")
	if classified.Kind != packageregistry.RequestArtifact || classified.Name != "foo-bar" || classified.Version != "2.0.0" {
		t.Fatalf("classified direct artifact = %#v", classified)
	}
}

func TestClassifyRegistryRequestUsesAdvertisedPyPICoreMetadataIdentity(t *testing.T) {
	repositories, err := packageregistry.NewCatalog([]string{"pypi"})
	if err != nil {
		t.Fatal(err)
	}
	repository, ok := repositories.RepositoryForEcosystem(packageregistry.EcosystemPyPI)
	if !ok {
		t.Fatal("PyPI repository is not configured")
	}
	baseURL, err := url.Parse("https://pypi.org/simple/example/")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := packageregistry.NewArtifactIndex()
	_, err = repository.FilterMetadata(packageregistry.MetadataInput{
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
		Request:     packageregistry.Request{Ecosystem: packageregistry.EcosystemPyPI, Name: "example"},
		Artifacts:   artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &registryEndpointRuntime{repositories: repositories, artifacts: artifacts}

	classified := classifyRegistryRequest(
		runtime,
		http.MethodGet,
		"files.pythonhosted.org",
		"/packages/opaque-download.metadata",
	)
	if classified.Kind != packageregistry.RequestArtifact || classified.Name != "example" || classified.Version != "1.0.0" {
		t.Fatalf("core metadata request = %#v", classified)
	}
}

func TestRegistryProxyFiltersMetadataAndBlocksDirectArtifact(t *testing.T) {
	feedServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/malware_predictions.json":
			_, _ = io.WriteString(writer, "[]")
		case "/releases/npm.json":
			_, _ = io.WriteString(writer, "[]")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer feedServer.Close()
	feedURL, err := url.Parse(feedServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(feedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(fmt.Sprintf(`{
  "version": 1,
  "settings": {"default_action": "allow", "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": %q, "filter_package_age": 24},
    "egress": [{"host": "127.0.0.1", "port": %s, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }],
  "rules": []
}`, feedServer.URL, portText)))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	route := router.New(hooks.NewPolicyHook(compiled), nil)
	certPath, keyPath, rootCAs := writeTestCA(t, t.TempDir())
	ca, err := loadCertificateAuthority(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := newRegistryProxy(route, ca, nil, feedServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxy.upstreamRootCAs = rootCAs

	metadata := `{
  "name":"example",
  "dist-tags":{"latest":"2.0.0","stable":"1.0.0"},
  "time":{"1.0.0":"2020-01-01T00:00:00Z","2.0.0":"2099-01-01T00:00:00Z"},
  "versions":{
    "1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}},
    "2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-2.0.0.tgz"}}
  }
}`
	requestCh := make(chan *http.Request, 1)
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nETag: upstream-metadata\r\nConnection: close\r\n\r\n%s", len(metadata), metadata)
	target, closeUpstream, _ := startObservedTLSUpstreamWithResponseForHost(t, certPath, keyPath, "registry.npmjs.org", requestCh, response)
	defer closeUpstream()

	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	flowDecision := routeDecision(t, route, flow)
	clientConn, proxyConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleTCP(context.Background(), proxyConn, flow, target, flowDecision)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "registry.npmjs.org"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(clientTLS)
	metadataRequest, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/example", nil)
	if err != nil {
		t.Fatal(err)
	}
	metadataRequest.Header.Set("If-None-Match", `"cached-metadata"`)
	metadataRequest.Header.Set("Range", "bytes=0-100")
	metadataRequest.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	if err := metadataRequest.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	metadataResponse, err := http.ReadResponse(reader, metadataRequest)
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Versions map[string]json.RawMessage `json:"versions"`
		DistTags map[string]string          `json:"dist-tags"`
	}
	if err := json.NewDecoder(metadataResponse.Body).Decode(&filtered); err != nil {
		t.Fatal(err)
	}
	_ = metadataResponse.Body.Close()
	if len(filtered.Versions) != 1 || filtered.Versions["1.0.0"] == nil || filtered.DistTags["latest"] != "1.0.0" {
		t.Fatalf("unexpected filtered metadata: %#v", filtered)
	}
	if metadataResponse.Header.Get("ETag") != "" {
		t.Fatalf("transformed metadata retained upstream ETag %q", metadataResponse.Header.Get("ETag"))
	}
	upstreamRequest := <-requestCh
	if upstreamRequest.Header.Get("If-None-Match") != `"cached-metadata"` || upstreamRequest.Header.Get("Range") != "bytes=0-100" || upstreamRequest.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected upstream metadata headers: %#v", upstreamRequest.Header)
	}

	artifactRequest, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/example/-/example-2.0.0.tgz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifactRequest.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	artifactResponse, err := http.ReadResponse(reader, artifactRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, artifactResponse.Body)
	_ = artifactResponse.Body.Close()
	if artifactResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("artifact status = %d, want %d", artifactResponse.StatusCode, http.StatusForbidden)
	}
	_ = clientTLS.Close()
	waitForProxy(t, done)
}

func TestRegistryProxyDoesNotFilterMalwareMetadata(t *testing.T) {
	feedServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/malware_predictions.json":
			_, _ = io.WriteString(writer, `[{"package_name":"valid-ip-scope","version":"0.0.1-security","reason":"MALWARE"}]`)
		case "/releases/npm.json":
			_, _ = io.WriteString(writer, "[]")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer feedServer.Close()
	feedURL, err := url.Parse(feedServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(feedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(fmt.Sprintf(`{
  "version": 1,
  "settings": {"default_action": "allow", "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": %q, "filter_package_age": 24},
    "egress": [{"host": "127.0.0.1", "port": %s, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }],
  "rules": [{
    "name": "block-known-malware",
    "endpoints": ["public"],
    "condition": "package.malware_data_available && package.malware",
    "verdict": "deny",
    "priority": 200,
    "reason": "package identified as malware"
  }]
}`, feedServer.URL, portText)))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
	if err != nil {
		t.Fatal(err)
	}
	route := router.New(hooks.NewPolicyHook(compiled), auditLog)
	certPath, keyPath, rootCAs := writeTestCA(t, t.TempDir())
	ca, err := loadCertificateAuthority(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := newRegistryProxy(route, ca, nil, feedServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxy.upstreamRootCAs = rootCAs

	metadata := `{
  "name":"valid-ip-scope",
  "dist-tags":{"latest":"0.0.1-security"},
  "time":{"0.0.1-security":"2025-04-04T14:07:15Z"},
  "versions":{"0.0.1-security":{"dist":{"tarball":"https://registry.npmjs.org/valid-ip-scope/-/valid-ip-scope-0.0.1-security.tgz"}}}
}`
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(metadata), metadata)
	target, closeUpstream, _ := startObservedTLSUpstreamWithResponseForHost(t, certPath, keyPath, "registry.npmjs.org", make(chan *http.Request, 1), response)
	defer closeUpstream()

	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53101, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	flowDecision := routeDecision(t, route, flow)
	clientConn, proxyConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleTCP(context.Background(), proxyConn, flow, target, flowDecision)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "registry.npmjs.org"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/valid-ip-scope", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	responseFromProxy, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(responseFromProxy.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = responseFromProxy.Body.Close()
	if responseFromProxy.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d, body %q", responseFromProxy.StatusCode, body)
	}
	var filtered struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &filtered); err != nil || len(filtered.Versions) != 1 {
		t.Fatalf("malware metadata = %q, %v", body, err)
	}
	_ = clientTLS.Close()
	waitForProxy(t, done)

	artifactFlow := flow
	artifactFlow.SourcePort++
	artifactClientConn, artifactProxyConn := net.Pipe()
	artifactDone := make(chan error, 1)
	go func() {
		artifactDone <- proxy.HandleTCP(context.Background(), artifactProxyConn, artifactFlow, target, flowDecision)
	}()
	artifactTLS := tls.Client(artifactClientConn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "registry.npmjs.org"})
	if err := artifactTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	artifactRequest, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/valid-ip-scope/-/valid-ip-scope-0.0.1-security.tgz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifactRequest.Write(artifactTLS); err != nil {
		t.Fatal(err)
	}
	artifactResponse, err := http.ReadResponse(bufio.NewReader(artifactTLS), artifactRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, artifactResponse.Body)
	_ = artifactResponse.Body.Close()
	if artifactResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("malware artifact status = %d", artifactResponse.StatusCode)
	}
	_ = artifactTLS.Close()
	waitForProxy(t, artifactDone)

	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	auditFile, err := os.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer auditFile.Close()
	decoder := json.NewDecoder(auditFile)
	var metadataEvent audit.Event
	if err := decoder.Decode(&metadataEvent); err != nil {
		t.Fatal(err)
	}
	if metadataEvent.Family != "package" || metadataEvent.Verdict != "allow" || metadataEvent.Reason != "" {
		t.Fatalf("unexpected metadata audit decision: %#v", metadataEvent)
	}
	if metadataEvent.Package == nil || metadataEvent.Package.Name != "valid-ip-scope" || metadataEvent.Package.Version != "" || metadataEvent.Package.IdentityKnown {
		t.Fatalf("unexpected metadata package facts: %#v", metadataEvent.Package)
	}
	var artifactEvent audit.Event
	if err := decoder.Decode(&artifactEvent); err != nil {
		t.Fatal(err)
	}
	if artifactEvent.Verdict != "deny" || artifactEvent.Reason != "package identified as malware" || artifactEvent.Policy == nil || artifactEvent.Policy.RuleName != "block-known-malware" {
		t.Fatalf("unexpected artifact audit decision: %#v", artifactEvent)
	}
	if artifactEvent.Package == nil || artifactEvent.Package.Operation != "download" || artifactEvent.Package.Name != "valid-ip-scope" || artifactEvent.Package.Version != "0.0.1-security" || !artifactEvent.Package.IdentityKnown || artifactEvent.Package.MalwareDataAvailable == nil || !*artifactEvent.Package.MalwareDataAvailable || artifactEvent.Package.Malware == nil || !*artifactEvent.Package.Malware {
		t.Fatalf("unexpected artifact package facts: %#v", artifactEvent.Package)
	}
	rawAudit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawAudit), "package_filter") {
		t.Fatalf("audit contains removed package_filter field: %s", rawAudit)
	}
}

func TestRegistryProxyPassesThroughMalformedMetadata(t *testing.T) {
	result := proxyNPMRegistryTestRequest(
		t,
		"deny",
		"/example",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nETag: upstream\r\nConnection: close\r\n\r\n{",
	)
	if result.status != http.StatusOK || string(result.body) != "{" || result.header.Get("ETag") != "upstream" {
		t.Fatalf("malformed metadata response = %d %q %#v", result.status, result.body, result.header)
	}
}

func TestRegistryProxyPassesThroughNPMNotModifiedMetadata(t *testing.T) {
	result := proxyNPMRegistryTestRequest(
		t,
		"allow",
		"/example",
		"HTTP/1.1 304 Not Modified\r\nETag: upstream-metadata\r\nConnection: close\r\n\r\n",
	)
	if result.status != http.StatusNotModified || len(result.body) != 0 || result.header.Get("ETag") != "upstream-metadata" {
		t.Fatalf("not-modified metadata response = %d %#v %q", result.status, result.header, result.body)
	}
}

func TestRegistryProxyPassesThroughNPMSpecialEndpoints(t *testing.T) {
	result := proxyNPMRegistryTestRequest(
		t,
		"deny",
		"/-/ping",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
	)
	if result.status != http.StatusOK || string(result.body) != "pong" {
		t.Fatalf("special endpoint response = %d %q", result.status, result.body)
	}
}

type registryTestResponse struct {
	status int
	header http.Header
	body   []byte
}

func proxyNPMRegistryTestRequest(t *testing.T, defaultAction string, requestPath string, upstreamResponse string) registryTestResponse {
	t.Helper()
	feedServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/malware_predictions.json", "/releases/npm.json":
			_, _ = io.WriteString(writer, "[]")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer feedServer.Close()
	feedURL, err := url.Parse(feedServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(feedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadReader("policy.json", strings.NewReader(fmt.Sprintf(`{
  "version": 1,
  "settings": {"default_action": %q, "audit": {}},
  "endpoints": [{
    "kind": "registries",
    "name": "public",
    "family": "package",
    "transport": "tls-terminate",
    "tls": "terminate",
    "config": {"registries": ["npm"], "malware_feed": %q, "filter_package_age": 24},
    "egress": [{"host": "127.0.0.1", "port": %s, "tls": true}],
    "hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"]
  }],
  "rules": []
}`, defaultAction, feedServer.URL, portText)))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	route := router.New(hooks.NewPolicyHook(compiled), nil)
	certPath, keyPath, rootCAs := writeTestCA(t, t.TempDir())
	ca, err := loadCertificateAuthority(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := newRegistryProxy(route, ca, nil, feedServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxy.upstreamRootCAs = rootCAs
	requestCh := make(chan *http.Request, 1)
	target, closeUpstream, _ := startObservedTLSUpstreamWithResponseForHost(t, certPath, keyPath, "registry.npmjs.org", requestCh, upstreamResponse)
	defer closeUpstream()

	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53102, DestIP: net.ParseIP("203.0.113.10"), DestPort: 443}
	flowDecision := routeDecision(t, route, flow)
	clientConn, proxyConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleTCP(context.Background(), proxyConn, flow, target, flowDecision)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "registry.npmjs.org"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org"+requestPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	return registryTestResponse{status: response.StatusCode, header: response.Header.Clone(), body: body}
}
