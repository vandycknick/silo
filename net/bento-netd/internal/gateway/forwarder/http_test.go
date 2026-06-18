package forwarder

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	"github.com/nickvan/bentobox/net/bento-netd/internal/policy"
)

func TestHTTPProxyInterceptsAllowedRequest(t *testing.T) {
	route := testRoute(t, `
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
	upstreamAddress, stopUpstream, _ := startPlainHTTPUpstream(t, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := httpFlow()
	flowDecision, err := route.Decide(context.Background(), flow)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if flowDecision.Action != hooks.RouteClassify {
		t.Fatalf("expected HTTP flow classification, got %#v", flowDecision)
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
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientConn.Close()
	waitForProxy(t, done)
	assertNoUpstreamAccept(t, acceptedCh)
}

func testRoute(t *testing.T, text string) *router.Router {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.hcl")
	if err := os.WriteFile(policyPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	return router.New(hooks.NewPolicyHook(compiled), nil)
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

func startPlainHTTPUpstream(t *testing.T, requestCh chan<- *http.Request) (string, func(), <-chan struct{}) {
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
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }, acceptedCh
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
