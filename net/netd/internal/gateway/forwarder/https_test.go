package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/bentobox/net/netd/internal/credentials"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/router"
)

func TestHTTPSProxyInterceptsAllowedRequest(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route, auditLog, auditPath, policyHash := testRouteWithAudit(t, `
settings {
  default_action = "deny"
}

endpoint "https" "local" {
  hosts = ["localhost"]
}

rule "local-reads" {
  endpoint = https.local
  condition = "http.method == 'GET'"
  verdict = "allow"
}
	`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startObservedTLSUpstreamWithResponseForHost(t, caCert, caKey, "localhost", requestCh, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace: allowed-https\r\nSet-Cookie: session=secret\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 53100,
		DestIP:     net.ParseIP("127.0.0.1"),
		DestPort:   443,
		FlowID:     "019f11a2-ff64-778d-8aa5-637c3921dfc9",
		VMID:       "vm-123",
		NetworkID:  "net-456",
	}
	flowDecision := routeDecision(t, route, flow)
	if flowDecision.Action != hooks.RouteClassify {
		t.Fatalf("expected HTTPS flow classification, got %#v", flowDecision)
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, flowDecision)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    caPool,
		ServerName: "localhost",
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()

	waitForProxy(t, done)
	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.URL.Path != "/private" {
			t.Fatalf("expected upstream request path /private, got %q", upstreamRequest.URL.Path)
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
	if event.Policy == nil || event.Policy.EndpointKind != "https" || event.Policy.EndpointName != "local" || event.Policy.RuleName != "local-reads" {
		t.Fatalf("unexpected policy metadata: %#v", event)
	}
	if event.HTTP == nil || event.HTTP.Scheme != "https" || event.HTTP.Request == nil || event.HTTP.Response == nil {
		t.Fatalf("unexpected HTTP metadata: %#v", event)
	}
	if event.HTTP.Request.Method != http.MethodGet || event.HTTP.Request.Host != "localhost" || event.HTTP.Request.Path != "/private" {
		t.Fatalf("unexpected HTTP request metadata: %#v", event.HTTP.Request)
	}
	if event.HTTP.Response.Status != http.StatusOK {
		t.Fatalf("unexpected HTTP response status: %#v", event.HTTP.Response)
	}
	if values := event.HTTP.Response.Headers["Content-Type"]; len(values) != 1 || values[0] != "application/json" {
		t.Fatalf("expected Content-Type response header, got %#v", event.HTTP.Response.Headers)
	}
	if values := event.HTTP.Response.Headers["X-Trace"]; len(values) != 1 || values[0] != "allowed-https" {
		t.Fatalf("expected X-Trace response header, got %#v", event.HTTP.Response.Headers)
	}
	if values := event.HTTP.Response.Headers["Set-Cookie"]; len(values) != 0 {
		t.Fatalf("expected Set-Cookie response header to be stripped, got %#v", values)
	}
}

func TestHTTPSProxyInterceptsWildcardEndpoint(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "https" "assets" {
  hosts = ["*.example.test"]
}

rule "asset-reads" {
  endpoint = https.assets
  condition = "http.method == 'GET'"
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startObservedTLSUpstreamForHost(t, caCert, caKey, "api.example.test", requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 53100,
		DestIP:     net.ParseIP("127.0.0.1"),
		DestPort:   443,
	}
	flowDecision := routeDecision(t, route, flow)
	if flowDecision.Action != hooks.RouteClassify {
		t.Fatalf("expected HTTPS wildcard flow classification, got %#v", flowDecision)
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, flowDecision)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    caPool,
		ServerName: "api.example.test",
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.test/assets/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()

	waitForProxy(t, done)
	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.Host != "api.example.test" {
			t.Fatalf("expected concrete wildcard host upstream, got %q", upstreamRequest.Host)
		}
	default:
		t.Fatal("upstream did not receive wildcard HTTPS request")
	}
}

func TestHTTPSProxyAppliesSelectedCredentialAndSanitizesHTTPFamilyHeaders(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "https" "local" {
  hosts = ["localhost"]
}

credential "bearer_token" "local" {
  endpoint = https.local
}

rule "allow-local" {
  endpoint = https.local
  verdict = "allow"
}
`)
	setHTTPSNetworkSecret(t, "local.token", "local-token")
	proxy, err := NewHTTPSProxy(route, caCert, caKey, credentials.NewManager())
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startObservedTLSUpstreamWithResponseForHost(t, caCert, caKey, "localhost", requestCh, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nSet-Cookie: session=secret\r\nWWW-Authenticate: Basic realm=\"git\"\r\nWWW-Authenticate: Bearer realm=\"api\"\r\nAlt-Svc: h3=\":443\"\r\n\r\nok")
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: caPool, ServerName: "localhost"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer guest-token")
	request.Header.Set("Proxy-Authorization", "Basic guest")
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "ok" {
		t.Fatalf("expected upstream body, got %q", body)
	}
	_ = clientTLS.Close()
	waitForProxy(t, done)

	upstreamRequest := <-requestCh
	if got := upstreamRequest.Header.Get("Authorization"); got != "Bearer local-token" {
		t.Fatalf("expected selected credential to overwrite Authorization, got %q", got)
	}
	if got := upstreamRequest.Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("expected Proxy-Authorization stripped, got %q", got)
	}
	if got := upstreamRequest.Header.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("expected X-Forwarded-For stripped, got %q", got)
	}
	if got := response.Header.Values("WWW-Authenticate"); len(got) != 1 || got[0] != `Basic realm="git"` {
		t.Fatalf("expected only Basic WWW-Authenticate to survive, got %#v", got)
	}
	for _, header := range []string{"Set-Cookie", "Alt-Svc"} {
		if values := response.Header.Values(header); len(values) != 0 {
			t.Fatalf("expected response header %s to be stripped, got %#v", header, values)
		}
	}
}

func TestHTTPSProxyCredentialSecretFailureDoesNotContactUpstream(t *testing.T) {
	logs := captureForwarderLogs(t)
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "https" "local" {
  hosts = ["localhost"]
}

credential "bearer_token" "local" {
  endpoint = https.local
}

rule "allow-local" {
  endpoint = https.local
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: caPool, ServerName: "localhost"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", response.StatusCode)
	}
	if body := readResponseBody(t, response); body != "credential_secret_error" {
		t.Fatalf("expected credential_secret_error response, got %q", body)
	}
	logText := logs.String()
	for _, want := range []string{"credential application failed", "credential_secret_error", "bearer_token", "credential_name\":\"local", "local.token", "localhost", "/private"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("expected credential failure log to contain %q, got %q", want, logText)
		}
	}
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func captureForwarderLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestHTTPSProxyDefaultDenyDoesNotContactUpstreamBeforeRequestAllow(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "https" "local" {
  hosts = ["localhost"]
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 53100,
		DestIP:     net.ParseIP("127.0.0.1"),
		DestPort:   443,
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    caPool,
		ServerName: "localhost",
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPSProxyRejectsNoSNIWithoutRawIPBindingBeforeUpstreamContact(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
endpoint "https" "api" {
  hosts = ["api.example.com"]
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err == nil {
		_ = clientTLS.Close()
		t.Fatal("expected no-SNI handshake to fail without a raw-IP HTTPS binding")
	}
	_ = clientTLS.Close()
	waitForProxyError(t, done, "missing_sni")
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPSProxyInterceptsNoSNIRawIPBindingOnConfiguredPort(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "https" "proxmox" {
  hosts = ["127.0.0.1:8006"]
}

rule "allow-proxmox" {
  endpoint = https.proxmox
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startObservedTLSUpstreamForHost(t, caCert, caKey, "127.0.0.1", requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 8006}
	flowDecision := routeDecision(t, route, flow)
	if flowDecision.Action != hooks.RouteClassify || !proxy.ShouldHandle(flow, flowDecision) {
		t.Fatalf("expected configured raw-IP port to classify, got decision=%#v should_handle=%v", flowDecision, proxy.ShouldHandle(flow, flowDecision))
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, flowDecision)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:8006/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)

	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.Host != "127.0.0.1:8006" {
			t.Fatalf("expected upstream Host 127.0.0.1:8006, got %q", upstreamRequest.Host)
		}
		if upstreamRequest.URL.Path != "/private" {
			t.Fatalf("expected upstream path /private, got %q", upstreamRequest.URL.Path)
		}
	default:
		t.Fatal("upstream did not receive request")
	}
}

func TestHTTPSProxyRejectsNoSNIRawIPHostMismatchWithoutUpstreamContact(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
endpoint "https" "proxmox" {
  hosts = ["127.0.0.1:8006"]
}

rule "allow-proxmox" {
  endpoint = https.proxmox
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstreamForHost(t, caCert, caKey, "127.0.0.1", requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 8006}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost:8006/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPSProxyRejectsNoSNIRawIPMissingHostWithoutUpstreamContact(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
endpoint "https" "proxmox" {
  hosts = ["127.0.0.1:8006"]
}

rule "allow-proxmox" {
  endpoint = https.proxmox
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstreamForHost(t, caCert, caKey, "127.0.0.1", requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 8006}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if _, err := fmt.Fprint(clientTLS, "GET /private HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatalf("write raw client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPSProxyExplicitIPAllowRawForwardsNoSNIWithoutRawIPBinding(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
settings {
  default_action = "deny"
}

endpoint "ip" "allowed" {
  destination = ["127.0.0.1/32"]
  protocol = "tcp"
  ports = [443]
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

rule "allow-ip" {
  endpoint = ip.allowed
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, _ := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	flowDecision := routeDecision(t, route, flow)
	if flowDecision.Action != hooks.RouteClassify || flowDecision.Source != "rule" {
		t.Fatalf("expected explicit ip allow to classify-or-forward, got %#v", flowDecision)
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, flowDecision)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)

	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.URL.Path != "/private" {
			t.Fatalf("expected upstream request path /private, got %q", upstreamRequest.URL.Path)
		}
	default:
		t.Fatal("upstream did not receive request")
	}
}

func TestHTTPSProxyRejectsHostMismatchWithoutUpstreamContact(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
endpoint "https" "local" {
  hosts = ["localhost"]
}

rule "allow-local" {
  endpoint = https.local
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: caPool, ServerName: "localhost"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://other.local/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestHTTPSProxyRejectsMissingHostWithoutUpstreamContact(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	route := testRoute(t, `
endpoint "https" "local" {
  hosts = ["localhost"]
}

rule "allow-local" {
  endpoint = https.local
  verdict = "allow"
}
`)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream, acceptedCh := startObservedTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{Protocol: "tcp", SourceIP: net.ParseIP("192.168.127.2"), SourcePort: 53100, DestIP: net.ParseIP("127.0.0.1"), DestPort: 443}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress, routeDecision(t, route, flow))
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: caPool, ServerName: "localhost"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if _, err := fmt.Fprint(clientTLS, "GET /private HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatalf("write raw client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func TestCertificateForReusesFreshCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCA(t, dir)
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cached, err := ca.mint("localhost", time.Now())
	if err != nil {
		t.Fatalf("mint returned error: %v", err)
	}
	cached.Leaf = nil
	ca.cache["localhost"] = cached

	returned, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if returned != cached {
		t.Fatal("expected fresh cached certificate to be reused")
	}
	if returned.Leaf == nil {
		t.Fatal("expected cached certificate leaf to be populated")
	}
}

func TestCertificateForRefreshesNearExpiryCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCA(t, dir)
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	nearExpiry, err := ca.mint("localhost", time.Now().Add(-23*time.Hour-30*time.Minute))
	if err != nil {
		t.Fatalf("mint near-expiry certificate: %v", err)
	}
	ca.cache["localhost"] = nearExpiry

	refreshed, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if refreshed == nearExpiry {
		t.Fatal("expected near-expiry certificate to be refreshed")
	}
	if ca.cache["localhost"] != refreshed {
		t.Fatal("expected refreshed certificate to replace cache entry")
	}
	if !refreshed.Leaf.NotAfter.After(nearExpiry.Leaf.NotAfter) {
		t.Fatalf("expected refreshed certificate to expire later than cached certificate, old=%s new=%s", nearExpiry.Leaf.NotAfter, refreshed.Leaf.NotAfter)
	}
}

func TestCertificateForReusesCALimitedCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCAExpiringAt(t, dir, time.Now().Add(30*time.Minute))
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cached, err := ca.mint("localhost", time.Now())
	if err != nil {
		t.Fatalf("mint returned error: %v", err)
	}
	if !cached.Leaf.NotAfter.Equal(ca.cert.NotAfter) {
		t.Fatalf("expected cached certificate expiry to be limited by CA, leaf=%s ca=%s", cached.Leaf.NotAfter, ca.cert.NotAfter)
	}
	ca.cache["localhost"] = cached

	returned, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if returned != cached {
		t.Fatal("expected CA-limited cached certificate to be reused")
	}
}

func startTLSUpstream(t *testing.T, caCertPath string, caKeyPath string, requestCh chan<- *http.Request) (string, func()) {
	address, stop, _ := startObservedTLSUpstream(t, caCertPath, caKeyPath, requestCh)
	return address, stop
}

func startObservedTLSUpstream(t *testing.T, caCertPath string, caKeyPath string, requestCh chan<- *http.Request) (string, func(), <-chan struct{}) {
	return startObservedTLSUpstreamForHost(t, caCertPath, caKeyPath, "localhost", requestCh)
}

func startObservedTLSUpstreamForHost(t *testing.T, caCertPath string, caKeyPath string, certHost string, requestCh chan<- *http.Request) (string, func(), <-chan struct{}) {
	return startObservedTLSUpstreamWithResponseForHost(t, caCertPath, caKeyPath, certHost, requestCh, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

func startObservedTLSUpstreamWithResponseForHost(t *testing.T, caCertPath string, caKeyPath string, certHost string, requestCh chan<- *http.Request, response string) (string, func(), <-chan struct{}) {
	t.Helper()
	ca, err := loadCertificateAuthority(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cert, err := ca.CertificateFor(certHost)
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
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
		_, _ = fmt.Fprint(conn, response)
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }, acceptedCh
}

func setHTTPSNetworkSecret(t *testing.T, slot string, value string) {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("BENTO_NET_SECRET_")
	lastUnderscore := false
	for _, r := range slot {
		if r >= 'a' && r <= 'z' {
			builder.WriteRune(r - 'a' + 'A')
			lastUnderscore = false
			continue
		}
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	t.Setenv(strings.TrimRight(builder.String(), "_"), base64.StdEncoding.EncodeToString([]byte(value)))
}

func waitForProxyError(t *testing.T, done <-chan error, want string) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("proxy error = %v, want containing %q", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy")
	}
}

func routeDecision(t *testing.T, route *router.Router, flow hooks.Flow) hooks.RouteDecision {
	t.Helper()
	decision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	return decision
}

func writeTestCA(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	return writeTestCAExpiringAt(t, dir, time.Now().Add(24*time.Hour))
}

func writeTestCAExpiringAt(t *testing.T, dir string, notAfter time.Time) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "BentoBox Test CA",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append test CA")
	}
	return certPath, keyPath, pool
}
