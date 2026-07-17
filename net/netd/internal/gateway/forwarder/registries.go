package forwarder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	packageregistry "github.com/vandycknick/silo/net/netd/internal/registry"
)

const maxRegistryMetadataBytes = 64 << 20

type metadataForwardResult struct {
	outcome  httpForwardOutcome
	decision hooks.RouteDecision
}

type registryMetadataPayload struct {
	decoded []byte
	wire    []byte
}

type RegistryProxy struct {
	route           *router.Router
	ca              *CertificateAuthority
	endpoints       map[string]*packageregistry.Endpoint
	fallback        *HTTPSProxy
	upstreamRootCAs *x509.CertPool
}

func NewRegistryProxy(route *router.Router, ca *CertificateAuthority, fallback *HTTPSProxy, intelligencePool *packageregistry.IntelligencePool) (*RegistryProxy, error) {
	return newRegistryProxy(route, ca, fallback, intelligencePool)
}

func newRegistryProxy(route *router.Router, ca *CertificateAuthority, fallback *HTTPSProxy, intelligencePool *packageregistry.IntelligencePool) (*RegistryProxy, error) {
	if route == nil || !route.HasRegistries() {
		return nil, nil
	}
	if ca == nil {
		return nil, fmt.Errorf("registry proxy requires a certificate authority")
	}
	proxy := &RegistryProxy{
		route:     route,
		ca:        ca,
		endpoints: make(map[string]*packageregistry.Endpoint),
		fallback:  fallback,
	}
	for _, config := range route.RegistryEndpoints() {
		endpoint, err := packageregistry.NewEndpoint(packageregistry.EndpointConfig{
			Repositories: config.Registries, MalwareFeed: config.MalwareFeed,
			MinimumPackageAgeHours: config.FilterPackageAge,
		}, intelligencePool)
		if err != nil {
			return nil, fmt.Errorf("configure registry endpoint %q: %w", config.Name, err)
		}
		proxy.endpoints[config.Name] = endpoint
	}
	return proxy, nil
}

func (p *RegistryProxy) ShouldHandle(flow hooks.Flow, decision hooks.RouteDecision) bool {
	return p != nil && decision.Action == hooks.RouteClassify && p.route.ShouldInterceptEndpoint("registries", flow.DestPort)
}

func (p *RegistryProxy) HandleTCP(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, flowDecision hooks.RouteDecision) error {
	sni, replayed, peekErr := peekClientHello(inbound)
	if peekErr != nil {
		if p.fallback != nil {
			return p.fallback.handleClientHello(ctx, sni, replayed, peekErr, flow, target, flowDecision)
		}
		if flowAllowsExplicitRawFallback(flowDecision) {
			return p.proxyDirect(ctx, replayed, target)
		}
		_ = replayed.Close()
		return peekErr
	}
	endpointName, authority, certificateHost, ok := p.route.ResolveEndpointHost("registries", sni, flow.DestPort)
	if !ok {
		if p.fallback != nil {
			return p.fallback.handleClientHello(ctx, sni, replayed, nil, flow, target, flowDecision)
		}
		if flowAllowsRawFallback(flowDecision) {
			return p.proxyDirect(ctx, replayed, target)
		}
		_ = replayed.Close()
		return fmt.Errorf("unclassified_registry: sni %q does not match a registry endpoint", sni)
	}
	runtime := p.endpoints[endpointName]
	if runtime == nil {
		_ = replayed.Close()
		return fmt.Errorf("registry endpoint %q has no runtime", endpointName)
	}
	serverTLS := tls.Server(replayed, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = certificateHost
			}
			return p.ca.CertificateFor(host)
		},
	})
	if err := serverTLS.HandshakeContext(ctx); err != nil {
		_ = serverTLS.Close()
		return err
	}
	return p.proxyHTTP(ctx, serverTLS, flow, target, endpointName, authority, certificateHost, runtime)
}

func (p *RegistryProxy) proxyDirect(ctx context.Context, inbound net.Conn, target string) error {
	outbound, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		_ = inbound.Close()
		return err
	}
	proxyTCP(inbound, outbound)
	return nil
}

func (p *RegistryProxy) proxyHTTP(ctx context.Context, client *tls.Conn, flow hooks.Flow, target string, endpointName string, authority string, upstreamServerName string, runtime *packageregistry.Endpoint) error {
	defer client.Close()
	reader := bufio.NewReader(client)
	for {
		req, err := http.ReadRequest(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		request := httpRequest(flow, "registries", req)
		resolvedName, _, _, hostMatches := p.route.ResolveEndpointHost("registries", req.Host, flow.DestPort)
		if req.Host == "" || !hostMatches || resolvedName != endpointName || !p.route.MatchEndpointAuthority("registries", req.Host, authority) {
			_ = req.Body.Close()
			status, body := http.StatusMisdirectedRequest, "host_mismatch"
			decision := deniedFlow(body)
			p.route.RecordHTTP(request, decision, status, httpStatusHeader(status, body))
			return writeHTTPStatus(client, status, body)
		}

		classified := runtime.Classify(req.Method, requestHost(req.Host), requestPath(req))

		if classified.Kind == packageregistry.RequestUnknown || (classified.Kind == packageregistry.RequestMetadata && (classified.Operation != "resolve" || req.Method != http.MethodGet || runtime.MinimumPackageAgeHours() == 0)) {
			decision := metadataRequestDecision(endpointName, classified)
			outcome, err := forwardHTTPFamilyRequest(ctx, client, reader, req, "https", authority, nil, nil, p.registryDial(ctx, target, upstreamServerName))
			p.route.RecordHTTPOutcome(request, decision, outcome.status, outcome.responseHeader, outcome.reason)
			if err != nil {
				return err
			}
			if req.Close {
				return nil
			}
			continue
		}

		if classified.Kind != packageregistry.RequestMetadata {
			candidate := packageregistry.Candidate{
				Ecosystem:        classified.Ecosystem,
				Operation:        classified.Operation,
				Name:             classified.Name,
				Version:          classified.Version,
				RegistryReleased: classified.RegistryReleased,
			}
			decision, err := p.evaluate(ctx, endpointName, request, runtime, candidate)
			if err != nil {
				_ = req.Body.Close()
				return err
			}
			decision = applyPackageAgeInvariant(decision, runtime.MinimumPackageAgeHours())
			if decision.Action == hooks.RouteDeny {
				_ = req.Body.Close()
				status, body := denyStatusAndBody(decision.Reason)
				p.route.RecordHTTP(request, decision, status, httpStatusHeader(status, body))
				return writeHTTPStatus(client, status, body)
			}
			outcome, err := forwardHTTPFamilyRequest(ctx, client, reader, req, "https", authority, nil, nil, p.registryDial(ctx, target, upstreamServerName))
			p.route.RecordHTTPOutcome(request, decision, outcome.status, outcome.responseHeader, outcome.reason)
			if err != nil {
				return err
			}
			if req.Close {
				return nil
			}
			continue
		}

		result, err := p.forwardMetadata(ctx, client, req, request, endpointName, authority, upstreamServerName, target, runtime, classified)
		p.route.RecordHTTPOutcome(request, result.decision, result.outcome.status, result.outcome.responseHeader, result.outcome.reason)
		if err != nil {
			return err
		}
		if result.decision.Action == hooks.RouteDeny {
			return nil
		}
		if req.Close {
			return nil
		}
	}
}

func (p *RegistryProxy) forwardMetadata(ctx context.Context, client net.Conn, req *http.Request, request hooks.HTTPRequest, endpointName string, authority string, upstreamServerName string, target string, runtime *packageregistry.Endpoint, classified packageregistry.Request) (metadataForwardResult, error) {
	defer req.Body.Close()
	result := metadataForwardResult{decision: metadataRequestDecision(endpointName, classified)}
	prepareNormalForwardRequest(req, "https", authority)
	req.Header.Del("Accept-Encoding")
	if err := runtime.PrepareMetadataRequest(classified.Ecosystem, req.Header); err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "registry_metadata_error")
		result.outcome = outcome
		return result, writeErr
	}
	outbound, err := p.registryDial(ctx, target, upstreamServerName)()
	if err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
		result.outcome = outcome
		return result, writeErr
	}
	defer outbound.Close()
	if err := req.Write(outbound); err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
		result.outcome = outcome
		return result, writeErr
	}
	response, err := http.ReadResponse(bufio.NewReader(outbound), req)
	if err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
		result.outcome = outcome
		return result, writeErr
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		sanitizeHTTPFamilyResponse(response, true)
		result.outcome = httpForwardOutcome{status: response.StatusCode, responseHeader: response.Header.Clone()}
		return result, response.Write(client)
	}
	payload, err := readRegistryMetadata(response)
	if err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "registry_metadata_error")
		result.outcome = outcome
		return result, writeErr
	}
	filtered, err := runtime.FilterMetadata(packageregistry.MetadataInput{
		Body:        payload.decoded,
		ContentType: response.Header.Get("Content-Type"),
		URL:         req.URL,
		Request:     classified,
	})
	if err != nil {
		outcome, writeErr := writeHTTPFamilyStatus(client, http.StatusBadGateway, "registry_metadata_error")
		result.outcome = outcome
		return result, writeErr
	}
	if filtered.Modified {
		result.decision.Reason = "minimum_package_age_filtered"
	}
	if !filtered.Modified {
		response.Body = io.NopCloser(bytes.NewReader(payload.wire))
		response.ContentLength = int64(len(payload.wire))
		response.TransferEncoding = nil
		response.Header.Del("Transfer-Encoding")
		response.Header.Set("Content-Length", strconv.Itoa(len(payload.wire)))
		sanitizeHTTPFamilyResponse(response, true)
		result.outcome = httpForwardOutcome{status: response.StatusCode, responseHeader: response.Header.Clone()}
		return result, response.Write(client)
	}
	response.Body = io.NopCloser(bytes.NewReader(filtered.Body))
	response.ContentLength = int64(len(filtered.Body))
	response.TransferEncoding = nil
	response.Header.Del("Content-Encoding")
	response.Header.Del("Transfer-Encoding")
	response.Header.Del("Accept-Ranges")
	response.Header.Del("Content-MD5")
	response.Header.Del("Content-Range")
	response.Header.Del("Digest")
	response.Header.Del("ETag")
	response.Header.Del("Last-Modified")
	response.Header.Set("Content-Length", strconv.Itoa(len(filtered.Body)))
	sanitizeHTTPFamilyResponse(response, true)
	result.outcome = httpForwardOutcome{status: response.StatusCode, responseHeader: response.Header.Clone()}
	return result, response.Write(client)
}

func metadataRequestDecision(endpointName string, request packageregistry.Request) hooks.RouteDecision {
	return hooks.RouteDecision{
		Action:       hooks.RouteAllowDirect,
		Layer:        "request",
		Source:       "registry",
		EndpointKind: "registries",
		EndpointName: endpointName,
		Package:      registryRequestPackage(request),
	}
}

func registryRequestPackage(request packageregistry.Request) *hooks.Package {
	return &hooks.Package{
		Ecosystem:     string(request.Ecosystem),
		Operation:     request.Operation,
		Name:          request.Name,
		Version:       request.Version,
		IdentityKnown: request.Name != "" && request.Version != "",
	}
}

func applyPackageAgeInvariant(decision hooks.RouteDecision, minimumAgeHours uint32) hooks.RouteDecision {
	if decision.Action == hooks.RouteDeny || minimumAgeHours == 0 || decision.Package == nil || !decision.Package.AgeKnown || decision.Package.AgeHours >= int64(minimumAgeHours) {
		return decision
	}
	decision.Action = hooks.RouteDeny
	decision.Source = "endpoint"
	decision.RuleName = ""
	decision.Reason = fmt.Sprintf("package was released less than %d hours ago", minimumAgeHours)
	return decision
}

func (p *RegistryProxy) evaluate(ctx context.Context, endpointName string, request hooks.HTTPRequest, runtime *packageregistry.Endpoint, candidate packageregistry.Candidate) (hooks.RouteDecision, error) {
	facts := runtime.Facts(candidate)
	query, err := url.ParseQuery(request.Query)
	if err != nil {
		return hooks.RouteDecision{}, err
	}
	packageRequest := policy.PackageRequest{
		Method: request.Method, Host: requestHost(request.Host), Path: request.Path,
		Query: mapStringLists(query, nil), Headers: mapStringLists(request.Header, strings.ToLower),
		Package: policy.PackageFacts{
			Ecosystem: facts.Ecosystem, Operation: facts.Operation, Name: facts.Name, Version: facts.Version,
			IdentityKnown: facts.IdentityKnown, AgeKnown: facts.AgeKnown, AgeHours: facts.AgeHours,
			AgeSource: facts.AgeSource, MalwareDataAvailable: facts.MalwareDataAvailable,
			Malware: facts.Malware, MalwareReason: facts.MalwareReason,
		},
	}
	return p.route.DecidePackage(ctx, "registries", endpointName, packageRequest)
}

func (p *RegistryProxy) registryDial(ctx context.Context, target string, serverName string) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			RootCAs:    p.upstreamRootCAs,
			ServerName: serverName,
		}}
		return dialer.DialContext(ctx, "tcp", target)
	}
}

func readRegistryMetadata(response *http.Response) (registryMetadataPayload, error) {
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxRegistryMetadataBytes+1))
	if err != nil {
		return registryMetadataPayload{}, err
	}
	if len(wire) > maxRegistryMetadataBytes {
		return registryMetadataPayload{}, fmt.Errorf("registry metadata exceeds %d bytes", maxRegistryMetadataBytes)
	}
	reader := io.Reader(bytes.NewReader(wire))
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" {
		if !strings.EqualFold(encoding, "gzip") {
			return registryMetadataPayload{decoded: wire, wire: wire}, nil
		}
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return registryMetadataPayload{}, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, maxRegistryMetadataBytes+1))
	if err != nil {
		return registryMetadataPayload{}, err
	}
	if len(decoded) > maxRegistryMetadataBytes {
		return registryMetadataPayload{}, fmt.Errorf("registry metadata exceeds %d bytes", maxRegistryMetadataBytes)
	}
	return registryMetadataPayload{decoded: decoded, wire: wire}, nil
}

func requestHost(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.ToLower(strings.TrimSuffix(authority, "."))
}

func mapStringLists[V ~[]string](values map[string]V, normalize func(string) string) map[string][]string {
	mapped := make(map[string][]string, len(values))
	for key, value := range values {
		if normalize != nil {
			key = normalize(key)
		}
		mapped[key] = append([]string(nil), value...)
	}
	return mapped
}
