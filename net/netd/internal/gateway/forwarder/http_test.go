package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/policy/policytest"
)

func TestHTTPProxyInterceptsAllowedRequest(t *testing.T) {
	route, auditLog, auditPath, policyHash := testRouteWithAudit(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

rule "allow-metadata" {
  endpoint = http.metadata
  condition = "http.method == 'GET'"
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstreamWithResponse(t, requestCh, newHTTPResponse(http.StatusOK, http.Header{
		"Content-Type": {"application/json"},
		"Set-Cookie":   {"session=secret"},
		"X-Trace":      {"allowed-http"},
	}, "ok"))
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flow.FlowID = "019f11a2-ff64-778d-8aa5-637c3921dfc9"
	flow.VMID = "vm-123"
	flow.NetworkID = "net-456"
	flowDecision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if flowDecision.Action != hooks.RouteClassify {
		t.Fatalf("expected HTTP flow classification, got %#v", flowDecision)
	}
	if !proxy.ShouldHandle(flow, flowDecision) {
		t.Fatalf("expected HTTP proxy to handle classified flow, got decision=%#v", flowDecision)
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)

	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.URL.Path != "/latest" {
			t.Fatalf("expected upstream request path /latest, got %q", upstreamRequest.URL.Path)
		}
	default:
		t.Fatal("upstream did not receive request")
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readForwarderAuditEvent(t, auditPath)
	if event.Version != 1 || event.Phase != "end" || event.Family != "http" || event.PolicyHash != policyHash {
		t.Fatalf("unexpected audit envelope: %#v", event)
	}
	if !isUUIDv7(event.RequestID) || event.FlowID != "" || event.ParentFlowID != flow.FlowID {
		t.Fatalf("unexpected audit ids: %#v", event)
	}
	if event.Verdict != "allow" || event.Reason != "" {
		t.Fatalf("unexpected audit verdict: %#v", event)
	}
	if event.VMID != "vm-123" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected runtime metadata: %#v", event)
	}
	if event.Policy == nil || event.Policy.EndpointKind != "http" || event.Policy.EndpointName != "metadata" || event.Policy.RuleName != "allow-metadata" {
		t.Fatalf("unexpected policy metadata: %#v", event)
	}
	if event.HTTP == nil || event.HTTP.Scheme != "http" || event.HTTP.Request == nil || event.HTTP.Response == nil {
		t.Fatalf("unexpected HTTP metadata: %#v", event)
	}
	if event.HTTP.Request.Method != http.MethodGet || event.HTTP.Request.Host != "metadata.internal" || event.HTTP.Request.Path != "/latest" {
		t.Fatalf("unexpected HTTP request metadata: %#v", event.HTTP.Request)
	}
	if event.HTTP.Response.Status != http.StatusOK {
		t.Fatalf("unexpected HTTP response status: %#v", event.HTTP.Response)
	}
	if values := event.HTTP.Response.Headers["Content-Type"]; len(values) != 1 || values[0] != "application/json" {
		t.Fatalf("expected Content-Type response header, got %#v", event.HTTP.Response.Headers)
	}
	if values := event.HTTP.Response.Headers["X-Trace"]; len(values) != 1 || values[0] != "allowed-http" {
		t.Fatalf("expected X-Trace response header, got %#v", event.HTTP.Response.Headers)
	}
	if values := event.HTTP.Response.Headers["Set-Cookie"]; len(values) != 0 {
		t.Fatalf("expected Set-Cookie response header to be stripped, got %#v", values)
	}
}

func TestHTTPProxyInterceptsConfiguredPort(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal:8080"]
}

rule "allow-metadata" {
  endpoint = http.metadata
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flow.DestPort = 8080
	flowDecision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if flowDecision.Action != hooks.RouteClassify || !proxy.ShouldHandle(flow, flowDecision) {
		t.Fatalf("expected configured HTTP port classification, got decision=%#v should_handle=%v", flowDecision, proxy.ShouldHandle(flow, flowDecision))
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal:8080/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)

	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.Host != "metadata.internal:8080" {
			t.Fatalf("expected upstream Host metadata.internal:8080, got %q", upstreamRequest.Host)
		}
	default:
		t.Fatal("upstream did not receive request")
	}
}

func TestHTTPProxyDoesNotHandleUnclassifiedPort(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal:8080"]
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}
	flow := httpFlow()
	flowDecision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if proxy.ShouldHandle(flow, flowDecision) {
		t.Fatalf("did not expect HTTP proxy to handle unconfigured port 80, got decision=%#v", flowDecision)
	}
}

func TestHTTPProxyDefaultDenyDoesNotContactUpstream(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "default_deny" {
		t.Fatalf("expected default_deny body, got %q", body)
	}
	_ = clientConn.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPProxyDefaultDenyWritesRequestAuditRecord(t *testing.T) {
	route, auditLog, auditPath, policyHash := testRouteWithAudit(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flow.FlowID = "019f11a2-ff64-778d-8aa5-637c3921dfc9"
	flow.VMID = "vm-123"
	flow.NetworkID = "net-456"
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/latest?debug=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer guest-secret")
	request.Header.Set("User-Agent", "curl/8.7.1")
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	_ = readResponseBody(t, response)
	_ = clientConn.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	event := readForwarderAuditEvent(t, auditPath)
	if event.Version != 1 || event.Phase != "end" || event.Family != "http" || event.PolicyHash != policyHash {
		t.Fatalf("unexpected audit envelope: %#v", event)
	}
	if !isUUIDv7(event.RequestID) || event.FlowID != "" || event.ParentFlowID != flow.FlowID {
		t.Fatalf("unexpected audit ids: %#v", event)
	}
	if event.Verdict != "deny" || event.Reason != "default_deny" {
		t.Fatalf("unexpected audit verdict: %#v", event)
	}
	if event.VMID != "vm-123" || event.NetworkID != "net-456" {
		t.Fatalf("unexpected runtime metadata: %#v", event)
	}
	if event.Policy == nil || event.Policy.EndpointKind != "http" || event.Policy.EndpointName != "metadata" || event.Policy.RuleName != "" {
		t.Fatalf("unexpected endpoint metadata: %#v", event)
	}
	if event.HTTP == nil || event.HTTP.Scheme != "http" || event.HTTP.Request == nil || event.HTTP.Response == nil {
		t.Fatalf("unexpected HTTP metadata: %#v", event)
	}
	if event.HTTP.Request.Method != http.MethodGet || event.HTTP.Request.Host != "metadata.internal" || event.HTTP.Request.Path != "/latest" || event.HTTP.Request.Query != "debug=1" {
		t.Fatalf("unexpected HTTP request metadata: %#v", event.HTTP.Request)
	}
	if event.HTTP.Response.Status != http.StatusForbidden {
		t.Fatalf("unexpected HTTP response metadata: %#v", event.HTTP.Response)
	}
	if values := event.HTTP.Response.Headers["Content-Type"]; len(values) != 1 || values[0] != "text/plain; charset=utf-8" {
		t.Fatalf("expected synthetic Content-Type response header, got %#v", event.HTTP.Response.Headers)
	}
	if values := event.HTTP.Request.Headers["Authorization"]; len(values) != 1 || values[0] != "<redacted>" {
		t.Fatalf("expected redacted Authorization header, got %#v", event.HTTP.Request.Headers)
	}
	if values := event.HTTP.Request.Headers["Accept"]; len(values) != 1 || values[0] != "application/json" {
		t.Fatalf("expected preserved Accept header, got %#v", event.HTTP.Request.Headers)
	}
	if values := event.HTTP.Request.Headers["User-Agent"]; len(values) != 1 || values[0] != "curl/8.7.1" {
		t.Fatalf("expected preserved User-Agent header, got %#v", event.HTTP.Request.Headers)
	}
	rawAudit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawAudit), "guest-secret") || strings.Contains(string(rawAudit), "profile_name") || strings.Contains(string(rawAudit), "l4_match") {
		t.Fatalf("audit record leaked forbidden data: %s", rawAudit)
	}
}

func TestHTTPProxyRejectsMissingAndInvalidHost(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "allow"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing", raw: "GET /latest HTTP/1.1\r\nConnection: close\r\n\r\n"},
		{name: "invalid", raw: "GET /latest HTTP/1.1\r\nHost: metadata.internal/path\r\nConnection: close\r\n\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := rawHTTPProxyResponse(t, proxy, httpFlow(), test.raw)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", response.StatusCode)
			}
		})
	}
}

func TestHTTPProxyUnknownHostDefaultDenyDoesNotContactUpstream(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://unknown.internal/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "default_deny" {
		t.Fatalf("expected default_deny body, got %q", body)
	}
	_ = clientConn.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPProxyUnknownHostDefaultAllowForwardsWithoutCredentials(t *testing.T) {
	route := testRoute(t, `
endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "bearer_token" "api" {
  endpoint = https.api
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://unknown.internal/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)

	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.Header.Get("Authorization") != "" {
			t.Fatalf("unknown HTTP host must not receive credential header, got %q", upstreamRequest.Header.Get("Authorization"))
		}
	default:
		t.Fatal("upstream did not receive default-allowed unknown host request")
	}
}

func TestHTTPProxySanitizesRequestsAndResponses(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

rule "allow-metadata" {
  endpoint = http.metadata
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	upstreamResponse := newHTTPResponse(http.StatusOK, http.Header{
		"Set-Cookie":                {"session=secret"},
		"WWW-Authenticate":          {`Basic realm="git", charset="UTF-8", Bearer realm="api"`},
		"Proxy-Authenticate":        {`Basic realm="proxy"`},
		"Authentication-Info":       {"secret"},
		"Proxy-Authentication-Info": {"secret"},
		"Alt-Svc":                   {`h3=":443"`},
		"X-Safe":                    {"yes"},
	}, "ok")
	upstreamResponse.ContentLength = -1
	upstreamResponse.TransferEncoding = []string{"chunked"}
	upstreamResponse.Trailer = http.Header{
		"Set-Cookie":          {"trailer=secret"},
		"WWW-Authenticate":    {`Basic realm="trailer"`},
		"Authentication-Info": {"trailer-secret"},
		"Alt-Svc":             {`h3=":443"`},
		"X-Trailer-Safe":      {"yes"},
	}
	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstreamWithResponse(t, requestCh, upstreamResponse)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, httpFlow(), upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/latest?debug=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Connection", "keep-alive, X-Hop")
	request.Header.Set("X-Hop", "remove-me")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("Proxy-Authorization", "Basic guest")
	request.Header.Set("Proxy-Authenticate", "Basic proxy")
	request.Header.Set("Te", "trailers")
	request.Header.Set("Trailers", "X-Trailer")
	request.Header.Set("Upgrade", "h2c")
	request.Header.Set("Cf-Ray", "ray")
	request.Header.Set("Cf-Worker", "worker")
	request.Header.Set("Cf-Ew-Via", "via")
	request.Header.Set("Cf-Connecting-Ip", "192.0.2.1")
	request.Header.Set("Cdn-Loop", "loop")
	request.Header.Set("X-Forwarded-For", "192.0.2.2")
	request.Header.Set("X-Forwarded-Host", "attacker.internal")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Via", "1.1 proxy")
	request.Header.Set("X-Keep", "yes")
	if err := request.WriteProxy(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "ok" {
		t.Fatalf("expected upstream body, got %q", body)
	}
	_ = clientConn.Close()
	waitForProxy(t, done)

	upstreamRequest := <-requestCh
	if upstreamRequest.RequestURI != "/latest?debug=1" {
		t.Fatalf("expected origin-form request target, got %q", upstreamRequest.RequestURI)
	}
	if upstreamRequest.URL.Scheme != "" || upstreamRequest.URL.Host != "" {
		t.Fatalf("expected origin-form URL at upstream, got %#v", upstreamRequest.URL)
	}
	if upstreamRequest.Host != "metadata.internal" {
		t.Fatalf("expected selected upstream Host, got %q", upstreamRequest.Host)
	}
	if upstreamRequest.Header.Get("X-Keep") != "yes" {
		t.Fatalf("expected unrelated header to be preserved, got %#v", upstreamRequest.Header.Values("X-Keep"))
	}
	for _, header := range []string{"Connection", "X-Hop", "Keep-Alive", "Proxy-Authorization", "Proxy-Authenticate", "Te", "Trailers", "Upgrade", "Cf-Ray", "Cf-Worker", "Cf-Ew-Via", "Cf-Connecting-Ip", "Cdn-Loop", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Via"} {
		if values := upstreamRequest.Header.Values(header); len(values) != 0 {
			t.Fatalf("expected request header %s to be stripped, got %#v", header, values)
		}
	}
	if got := response.Header.Values("WWW-Authenticate"); len(got) != 1 || got[0] != `Basic realm="git", charset="UTF-8"` {
		t.Fatalf("expected only Basic WWW-Authenticate to survive, got %#v", got)
	}
	for _, header := range []string{"Set-Cookie", "Proxy-Authenticate", "Authentication-Info", "Proxy-Authentication-Info", "Alt-Svc"} {
		if values := response.Header.Values(header); len(values) != 0 {
			t.Fatalf("expected response header %s to be stripped, got %#v", header, values)
		}
	}
	if got := response.Header.Get("X-Safe"); got != "yes" {
		t.Fatalf("expected safe response header to survive, got %q", got)
	}
	for _, header := range []string{"Set-Cookie", "WWW-Authenticate", "Authentication-Info", "Alt-Svc"} {
		if values := response.Trailer.Values(header); len(values) != 0 {
			t.Fatalf("expected response trailer %s to be stripped, got %#v", header, values)
		}
	}
	if got := response.Trailer.Get("X-Trailer-Safe"); got != "yes" {
		t.Fatalf("expected safe response trailer to survive, got %q", got)
	}
}

func TestHTTPProxyHostPortMismatchDoesNotContactUpstream(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

endpoint "http" "admin" {
  hosts = ["admin.internal:8080"]
}

rule "allow-admin" {
  endpoint = http.admin
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flow.DestPort = 80
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://admin.internal:8080/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "host_mismatch" {
		t.Fatalf("expected host_mismatch body, got %q", body)
	}
	_ = clientConn.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPProxyWebSocketUpgradeRelaysOpaqueFrames(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal"]
}

rule "allow-websocket" {
  endpoint = http.metadata
  condition = "http.method == 'GET'"
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, frameCh := startPlainWebSocketUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	clientReader := bufio.NewReader(clientConn)
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, httpFlow(), upstreamAddress)
	}()

	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", "test-key")
	request.Header.Set("Proxy-Authorization", "Basic guest")
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}
	response, err := http.ReadResponse(clientReader, request)
	if err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", response.StatusCode)
	}
	for _, header := range []string{"Set-Cookie", "WWW-Authenticate", "Alt-Svc"} {
		if values := response.Header.Values(header); len(values) != 0 {
			t.Fatalf("expected websocket response header %s to be stripped, got %#v", header, values)
		}
	}
	if got := response.Header.Get("Upgrade"); got != "websocket" {
		t.Fatalf("expected Upgrade handshake header to survive, got %q", got)
	}
	if got := response.Header.Get("Sec-WebSocket-Accept"); got != "test" {
		t.Fatalf("expected Sec-WebSocket-Accept to survive, got %q", got)
	}
	if got := response.Header.Get("X-Custom"); got != "keep" {
		t.Fatalf("expected custom handshake header to survive, got %q", got)
	}

	clientFrame := []byte{0x81, 0x02, 'h', 'i'}
	if _, err := clientConn.Write(clientFrame); err != nil {
		t.Fatalf("write client websocket frame: %v", err)
	}
	serverFrame := make([]byte, 4)
	if _, err := io.ReadFull(clientReader, serverFrame); err != nil {
		t.Fatalf("read upstream websocket frame: %v", err)
	}
	if !bytes.Equal(serverFrame, []byte{0x82, 0x02, 'o', 'k'}) {
		t.Fatalf("expected opaque upstream frame, got %#v", serverFrame)
	}
	_ = clientConn.Close()
	waitForProxy(t, done)

	upstreamFrame := <-frameCh
	if !bytes.Equal(upstreamFrame, clientFrame) {
		t.Fatalf("expected upstream to receive opaque client frame %#v, got %#v", clientFrame, upstreamFrame)
	}
	upstreamRequest := <-requestCh
	if upstreamRequest.Host != "metadata.internal" {
		t.Fatalf("expected websocket Host to be selected upstream authority, got %q", upstreamRequest.Host)
	}
	if upstreamRequest.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("expected Proxy-Authorization redacted from websocket handshake, got %q", upstreamRequest.Header.Get("Proxy-Authorization"))
	}
	if upstreamRequest.Header.Get("Connection") == "" || upstreamRequest.Header.Get("Upgrade") != "websocket" || upstreamRequest.Header.Get("Sec-WebSocket-Key") != "test-key" {
		t.Fatalf("expected websocket handshake headers to survive, got %#v", upstreamRequest.Header)
	}
}

func TestHTTPProxyTreatsConnectAsOrdinaryHTTPMethod(t *testing.T) {
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal:443"]
}

rule "allow-connect" {
  endpoint = http.metadata
  condition = "http.method == 'CONNECT'"
  verdict = "allow"
}
`)
	proxy := NewHTTPProxy(route)
	if proxy == nil {
		t.Fatal("expected HTTP proxy")
	}

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstreamWithResponse(t, requestCh, newHTTPResponse(http.StatusNoContent, nil, ""))
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flow.DestPort = 443
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	request := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: "metadata.internal:443"},
		Host:       "metadata.internal:443",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	request.Header.Set("Proxy-Authorization", "Basic guest")
	request.Header.Set("Connection", "close")
	if err := request.Write(clientConn); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected upstream 204, got %d", response.StatusCode)
	}
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)

	upstreamRequest := <-requestCh
	if upstreamRequest.Method != http.MethodConnect {
		t.Fatalf("expected upstream CONNECT request, got %s", upstreamRequest.Method)
	}
	if upstreamRequest.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("expected Proxy-Authorization stripped from CONNECT, got %q", upstreamRequest.Header.Get("Proxy-Authorization"))
	}
}

func TestRequestPathUsesParsedPath(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://metadata.internal/%7Euser?raw=%2Fignored", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestPath(request); got != "/~user" {
		t.Fatalf("expected parsed path /~user, got %q", got)
	}

	request, err = http.NewRequest(http.MethodGet, "http://metadata.internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestPath(request); got != "/" {
		t.Fatalf("expected empty path fallback /, got %q", got)
	}
}

func testRoute(t *testing.T, text string) *router.Router {
	t.Helper()
	compiled := testPolicy(t, text)
	return router.New(hooks.NewPolicyHook(compiled), nil)
}

func testRouteWithAudit(t *testing.T, text string) (*router.Router, *audit.Logger, string, string) {
	t.Helper()
	compiled := testPolicy(t, text)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.Open(auditPath, compiled.PolicyHash())
	if err != nil {
		t.Fatal(err)
	}
	return router.New(hooks.NewPolicyHook(compiled), auditLog), auditLog, auditPath, compiled.PolicyHash()
}

func testPolicy(t *testing.T, text string) *policy.Policy {
	t.Helper()
	return policytest.LoadPolicy(t, text)
}

func readForwarderAuditEvent(t *testing.T, path string) audit.Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var event audit.Event
	if err := json.NewDecoder(file).Decode(&event); err != nil {
		t.Fatal(err)
	}
	return event
}

func isUUIDv7(value string) bool {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value)
}

func httpFlow() hooks.Flow {
	return hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 53100,
		DestIP:     net.ParseIP("169.254.169.254"),
		DestPort:   80,
	}
}

func rawHTTPProxyResponse(t *testing.T, proxy *HTTPProxy, flow hooks.Flow, raw string) *http.Response {
	t.Helper()
	clientConn, proxyConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, "127.0.0.1:1")
	}()
	if _, err := clientConn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)
	return response
}

func startPlainHTTPUpstream(t *testing.T, requestCh chan<- *http.Request) (string, func(), <-chan struct{}) {
	return startPlainHTTPUpstreamWithResponse(t, requestCh, newHTTPResponse(http.StatusOK, nil, "ok"))
}

func startPlainHTTPUpstreamWithResponse(t *testing.T, requestCh chan<- *http.Request, response *http.Response) (string, func(), <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	acceptedCh := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case acceptedCh <- struct{}{}:
		default:
		}
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		requestCh <- request
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_ = response.Write(conn)
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }, acceptedCh
}

func startPlainWebSocketUpstream(t *testing.T, requestCh chan<- *http.Request) (string, func(), <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	frameCh := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		requestCh <- request
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: websocket\r\n" +
			"Sec-WebSocket-Accept: test\r\n" +
			"X-Custom: keep\r\n" +
			"Set-Cookie: session=secret\r\n" +
			"WWW-Authenticate: Basic realm=\"proxy\"\r\n" +
			"\tfolded-secret\r\n" +
			"Alt-Svc: h3=\":443\"\r\n" +
			"\r\n"))
		frame := make([]byte, 4)
		if _, err := io.ReadFull(reader, frame); err != nil {
			return
		}
		frameCh <- frame
		_, _ = conn.Write([]byte{0x82, 0x02, 'o', 'k'})
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }, frameCh
}

func newHTTPResponse(statusCode int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	} else {
		header = header.Clone()
	}
	response := &http.Response{
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          http.NoBody,
		ContentLength: 0,
	}
	if body != "" {
		response.Body = io.NopCloser(bytes.NewBufferString(body))
		response.ContentLength = int64(len(body))
	}
	return response
}

func readResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	return string(body)
}

func waitForProxy(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxy returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy")
	}
}

func assertNoUpstreamAccept(t *testing.T, acceptedCh <-chan struct{}) {
	t.Helper()
	select {
	case <-acceptedCh:
		t.Fatal("upstream accepted a connection before policy allowed the request")
	default:
	}
}
