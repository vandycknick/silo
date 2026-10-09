package netnode

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
)

type forwardFlows struct {
	draining atomic.Bool
	active   atomic.Int32
}

func (f *forwardFlows) Start() bool {
	if f.draining.Load() {
		return false
	}
	f.active.Add(1)
	if f.draining.Load() {
		f.active.Add(-1)
		return false
	}
	return true
}
func (f *forwardFlows) Done()       { f.active.Add(-1) }
func (f *forwardFlows) BeginDrain() { f.draining.Store(true) }

type forwardGuest struct {
	address string
	calls   atomic.Int32
	port    atomic.Uint32
}

func (g *forwardGuest) DialGuest(ctx context.Context, port uint16) (net.Conn, error) {
	g.calls.Add(1)
	g.port.Store(uint32(port))
	return (&net.Dialer{}).DialContext(ctx, "tcp", g.address)
}
func forwardNode(t *testing.T, guest Guest) (*Node, chan InboundEvent) {
	t.Helper()
	events := make(chan InboundEvent, 1024)
	n := newTestNode(t, Options{Guest: guest, Flows: &forwardFlows{}, Audit: func(e InboundEvent) { events <- e }})
	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.started = true
	n.lastKnown = &Observation{DNSName: "example.com"}
	t.Cleanup(func() { n.mu.Lock(); n.closed = true; n.cancel(); n.mu.Unlock(); n.relays.Wait() })
	return n, events
}
func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(5 * time.Second))
	return client, server
}
func TestForwardTCPGuestPortAndHalfClose(t *testing.T) {
	guest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := guest.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		c.Write(append([]byte("reply:"), b...))
		c.(*net.TCPConn).CloseWrite()
	}()
	dialer := &forwardGuest{address: guest.Addr().String()}
	n, events := forwardNode(t, dialer)
	client, raw := socketPair(t)
	defer client.Close()
	lease := n.admit(raw, InboundEvent{Forward: "raw", Port: 18080, TargetPort: 8080, Protocol: "tcp", Decision: "deny"}, "")
	go func() { defer lease.Close(); n.relayGuest(lease, 8080) }()
	client.Write([]byte("unchanged\x00payload"))
	client.(*net.TCPConn).CloseWrite()
	body, err := io.ReadAll(client)
	if err != nil || string(body) != "reply:unchanged\x00payload" {
		t.Fatalf("%q %v", body, err)
	}
	<-done
	select {
	case e := <-events:
		if e.Decision != "allow" || e.Reason != "connected" || e.TargetPort != 8080 {
			t.Fatalf("%+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing terminal event")
	}
	if dialer.port.Load() != 8080 {
		t.Fatal("listener port used as guest destination")
	}
}
func TestForwardReservedFallbackNeverDialsGuest(t *testing.T) {
	guest := &forwardGuest{address: "127.0.0.1:1"}
	n, events := forwardNode(t, guest)
	n.reserved = map[uint16]policy.Forward{18080: {Name: "raw", ListenPort: 18080, GuestPort: 8080, Protocol: policy.ForwardProtocolTCP}}
	client, in := socketPair(t)
	defer client.Close()
	handler, intercept := n.Fallback(netip.MustParseAddrPort("100.64.0.1:1234"), netip.MustParseAddrPort("100.64.0.2:18080"))
	if !intercept {
		t.Fatal("reserved port not intercepted")
	}
	go handler(in)
	io.ReadAll(client)
	if e := <-events; e.Reason != "forward_unavailable" {
		t.Fatalf("%+v", e)
	} else if e.Forward != "raw" || e.TargetPort != 8080 || e.Protocol != "tcp" {
		t.Fatalf("reserved forward lost audit attribution: %+v", e)
	}
	if guest.calls.Load() != 0 {
		t.Fatal("reserved port reached guest")
	}
}
func localForwardTLS(t *testing.T, n *Node) (string, *http.Client, func()) {
	t.Helper()
	// A generated stdlib test certificate proves local TLS transport only, not
	// managed Tailscale issuance. Production certificate eligibility is separate.
	issuer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := issuer.TLS.Certificates[0]
	root := issuer.Certificate()
	issuer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &admissionListener{Listener: raw, node: n, forward: policy.Forward{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS}}
	cleanup := n.serveForwardTLS(n.ctx, l, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", raw.Addr().String())
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return raw.Addr().String(), client, func() { transport.CloseIdleConnections(); cleanup() }
}
func TestForwardHTTPSProxyAuthorityHeadersStreamingAndUpgrade(t *testing.T) {
	observed := make(chan string, 4)
	streamRelease := make(chan struct{})
	defer close(streamRelease)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stream":
			w.Write([]byte("first\n"))
			w.(http.Flusher).Flush()
			select {
			case <-streamRelease:
			case <-r.Context().Done():
				return
			}
			w.Write([]byte("second\n"))
		case "/upgrade":
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			rw.Flush()
			line, _ := rw.ReadString('\n')
			fmt.Fprint(rw, "echo:"+line)
			rw.Flush()
		default:
			b, _ := io.ReadAll(r.Body)
			observed <- fmt.Sprintf("%s %s %s %s %s %s %s", r.Method, r.URL.RequestURI(), b, r.Host, r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Forwarded"))
			w.WriteHeader(201)
			w.Write([]byte("backend"))
		}
	}))
	defer backend.Close()
	guest := &forwardGuest{address: strings.TrimPrefix(backend.URL, "http://")}
	n, events := forwardNode(t, guest)
	addr, client, cleanup := localForwardTLS(t, n)
	defer cleanup()
	req, _ := http.NewRequest("POST", "https://example.com/a%2Fb?q=x%2By", strings.NewReader("payload"))
	req.Header.Set("Forwarded", "for=spoof")
	req.Header.Set("X-Forwarded-Host", "spoof")
	req.Header.Set("X-Forwarded-Proto", "spoof")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 201 || string(body) != "backend" {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	if got := <-observed; got != "POST /a%2Fb?q=x%2By payload example.com example.com https " {
		t.Fatalf("headers: %q", got)
	}
	calls := guest.calls.Load()
	req, _ = http.NewRequest("GET", "https://example.com/", nil)
	req.Host = "attacker.invalid"
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 421 || guest.calls.Load() != calls {
		t.Fatal("wrong Host reached guest")
	}
	req, _ = http.NewRequest("CONNECT", "https://example.com/", nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 405 {
		t.Fatal("CONNECT accepted")
	}
	n.mu.Lock()
	n.options.Identity = &ExpectedIdentity{}
	n.running = false
	n.mu.Unlock()
	res, err = client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 503 || guest.calls.Load() != calls {
		t.Fatal("keepalive request bypassed changed traffic gate")
	}
	n.mu.Lock()
	n.options.Identity = nil
	n.mu.Unlock()
	res, err = client.Get("https://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("stream: %q %v", line, err)
	}
	res.Body.Close()
	config := client.Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	reader := bufio.NewReader(conn)
	upgrade, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || upgrade.StatusCode != 101 {
		t.Fatalf("upgrade %v %v", upgrade, err)
	}
	fmt.Fprint(conn, "bidirectional\n")
	line, err = reader.ReadString('\n')
	if err != nil || line != "echo:bidirectional\n" {
		t.Fatalf("upgrade data: %q %v", line, err)
	}
	conn.Close()
	n.cancel()
	cleanup()
	n.relays.Wait()
	if len(n.active) != 0 {
		t.Fatal("active sockets survived shutdown")
	}
	if len(events) < 2 {
		t.Fatal("missing terminal audit")
	}
	for len(events) != 0 {
		if e := <-events; e.Forward != "web" || e.Protocol != "https" {
			t.Fatalf("%+v", e)
		}
	}
}
func TestForwardHTTPSGuestRefusalAndHandshakeFailure(t *testing.T) {
	guest := &forwardGuest{address: "127.0.0.1:1"}
	n, events := forwardNode(t, guest)
	addr, client, cleanup := localForwardTLS(t, n)
	defer cleanup()
	res, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 502 || string(body) != "Bad Gateway\n" {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	before := guest.calls.Load()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(raw, "not TLS\n")
	raw.Close()
	n.cancel()
	cleanup()
	n.relays.Wait()
	if guest.calls.Load() != before {
		t.Fatal("failed handshake contacted guest")
	}
	for len(events) != 0 {
		e := <-events
		if e.Decision == "allow" {
			t.Fatalf("failed connection allowed: %+v", e)
		}
	}
}
func TestForwardCertificateExactIdentity(t *testing.T) {
	s := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{DNSName: "web.tail.ts.net."}, CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true}, CertDomains: []string{"web.tail.ts.net"}}
	for _, sni := range []string{"web.tail.ts.net", "WEB.TAIL.TS.NET."} {
		if name, err := certificateName(s, nil, "web", sni); err != nil || name != "web.tail.ts.net" {
			t.Fatalf("%s: %q %v", sni, name, err)
		}
	}
	for _, sni := range []string{"", "web", "127.0.0.1", "*.tail.ts.net", "other.tail.ts.net", "web.tail.ts.net.."} {
		if _, err := certificateName(s, nil, "web", sni); err == nil {
			t.Fatalf("accepted %q", sni)
		}
	}
	s.CurrentTailnet.MagicDNSEnabled = false
	if _, err := certificateName(s, nil, "web", "web.tail.ts.net"); err == nil {
		t.Fatal("disabled MagicDNS accepted")
	}
}
func TestForwardNodeAttachmentScopeBeforeState(t *testing.T) {
	for _, protocol := range []policy.ForwardProtocol{policy.ForwardProtocolTCP, policy.ForwardProtocolHTTPS} {
		for _, scope := range []policy.AttachmentScope{policy.AttachmentScopeUnknown, policy.AttachmentScopeSharedNetwork, policy.AttachmentScopeDedicatedVM} {
			dir := t.TempDir()
			n, err := New(Options{Dir: dir, AttachmentScope: scope, Forwards: []policy.Forward{{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: protocol}}})
			if scope == policy.AttachmentScopeDedicatedVM {
				if err != nil {
					t.Fatal(err)
				}
				if err := n.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "dedicated 1:1") {
				t.Fatalf("scope %v: %v", scope, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("constructor created state: %v %v", entries, err)
			}
		}
	}
}

func TestForwardAdmissionSharedLimitDrainingAndAcceptRecovery(t *testing.T) {
	n, events := forwardNode(t, nil)
	var held []*admittedConn
	for i := range 256 {
		client, raw := socketPair(t)
		t.Cleanup(func() { client.Close() })
		event := InboundEvent{Port: 8080, Decision: "deny"}
		if i%2 == 0 {
			event.Forward, event.Port, event.Protocol = "web", 443, "https"
		}
		lease := n.admit(raw, event, "")
		if lease == nil {
			t.Fatal("slot rejected early")
		}
		held = append(held, lease)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawListener.Close()
	listener := &admissionListener{Listener: rawListener, node: n, forward: policy.Forward{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS}}
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	denied, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	denied.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := denied.Read(make([]byte, 1)); err == nil {
		t.Fatal("257th admitted")
	}
	denied.Close()
	if e := <-events; e.Reason != "connection_limit" {
		t.Fatalf("%+v", e)
	}
	held[0].Close()
	<-events
	allowed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	select {
	case conn := <-accepted:
		if conn == nil {
			t.Fatal("denial terminated Accept")
		}
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not recover")
	}
	for _, c := range held {
		c.Close()
	}
	n.options.Flows.(*forwardFlows).BeginDrain()
	client, in := socketPair(t)
	defer client.Close()
	if c := n.admit(in, InboundEvent{Decision: "deny"}, ""); c != nil {
		t.Fatal("draining admitted flow")
	}
	n.cancel()
	n.relays.Wait()
	found := false
	for len(events) != 0 {
		if e := <-events; e.Reason == "session_draining" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing drain audit")
	}
}

func TestForwardPartialBindRollbackAndReservation(t *testing.T) {
	n := newTestNode(t, Options{Dir: t.TempDir(), AttachmentScope: policy.AttachmentScopeDedicatedVM, Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "offline-forward", ControlURL: "http://127.0.0.1:1"}, Forwards: []policy.Forward{{Name: "first", ListenPort: 18080, GuestPort: 8080, Protocol: policy.ForwardProtocolTCP}, {Name: "collision", ListenPort: 18080, GuestPort: 8081, Protocol: policy.ForwardProtocolTCP}}})
	if err := n.server.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.server.Close()
	n.initialized = true
	if cleanup, err := n.startForwards(context.Background()); err == nil {
		cleanup()
		t.Fatal("duplicate binding succeeded")
	}
	listener, err := n.Listen("tcp", ":18080")
	if err != nil {
		t.Fatalf("partial binding leaked: %v", err)
	}
	listener.Close()
	listener, err = n.Listen("tcp", ":18080")
	if err != nil {
		t.Fatalf("restart cannot bind: %v", err)
	}
	listener.Close()
	if _, reserved := n.reserved[18080]; !reserved {
		t.Fatal("failed binding lost reservation")
	}
}

func TestForwardForceCloseStalledTLSAndTerminalAudit(t *testing.T) {
	n, events := forwardNode(t, nil)
	address, _, cleanup := localForwardTLS(t, n)
	defer cleanup()
	stalled, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	// A partial TLS header holds the server in its real handshake path.
	stalled.Write([]byte{0x16, 0x03})
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		count := len(n.active)
		n.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TLS socket not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	n.cancel()
	cleanup()
	n.relays.Wait()
	select {
	case e := <-events:
		if e.Reason != "tls_handshake_failed" || e.Decision != "deny" {
			t.Fatalf("%+v", e)
		}
	default:
		t.Fatal("join preceded audit")
	}
	stalled.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalled.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled TLS survived")
	}
}

func TestForwardCertificateRealLocalClientCancellationAndClosedNode(t *testing.T) {
	n := newTestNode(t, Options{Dir: t.TempDir(), Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "offline-cert", ControlURL: "http://127.0.0.1:1"}})
	n.Start(context.Background())
	defer n.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		ready := n.client != nil
		n.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real local client did not initialize")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := n.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := client.CertPairWithValidity(ctx, "offline-cert.tail.ts.net", 24*time.Hour); err == nil {
		t.Fatal("canceled certificate request succeeded")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.LocalClient(); err == nil {
		t.Fatal("closed node exposed certificate API")
	}
	if _, err := n.Listen("tcp", ":18080"); err == nil {
		t.Fatal("closed node admitted listener")
	}
}

type delayedForwardGuest struct {
	address                      string
	connected, canceled, release chan struct{}
}

func (g *delayedForwardGuest) DialGuest(ctx context.Context, _ uint16) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", g.address)
	if err != nil {
		return nil, err
	}
	close(g.connected)
	<-ctx.Done()
	close(g.canceled)
	<-g.release
	return c, nil
}
func TestForwardTransportJoinsLateRealSocketDial(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	guest := &delayedForwardGuest{address: backend.Addr().String(), connected: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	n, _ := forwardNode(t, guest)
	_, transport := n.forwardProxy(n.ctx, 8080, 443)
	result := make(chan error, 1)
	go func() {
		c, err := transport.dial(context.Background(), "tcp", "ignored.invalid:1234")
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	peer, err := backend.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	<-guest.connected
	joined := make(chan struct{})
	go func() { transport.close(); close(joined) }()
	select {
	case <-guest.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("service cancellation did not reach dial")
	}
	select {
	case <-joined:
		t.Fatal("shutdown abandoned pending dial")
	default:
	}
	close(guest.release)
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("late dial did not join")
	}
	if err := <-result; err == nil {
		t.Fatal("late socket published after close")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("upstream socket survived: %v", err)
	}
	if _, err := transport.dial(context.Background(), "tcp", "ignored.invalid:1"); err == nil {
		t.Fatal("closed service registered new work")
	}
}

func TestForwardAuditWaitsForRequestAndRejectsTerminalMutation(t *testing.T) {
	n, events := forwardNode(t, nil)
	client, raw := socketPair(t)
	defer client.Close()
	c := n.admit(raw, InboundEvent{Forward: "web", Decision: "deny", Reason: "guest_not_contacted"}, "")
	if !c.acquire() {
		t.Fatal("request reference rejected")
	}
	c.Close()
	select {
	case <-events:
		t.Fatal("audit raced active request")
	default:
	}
	c.outcome("connected", true)
	c.release()
	e := <-events
	if e.Decision != "allow" || e.Reason != "connected" {
		t.Fatalf("%+v", e)
	}
	c.outcome("http_host_mismatch", false)
	c.mu.Lock()
	terminal := c.event
	c.mu.Unlock()
	if terminal.Reason != "connected" {
		t.Fatal("terminal outcome mutated")
	}
	select {
	case <-events:
		t.Fatal("duplicate audit")
	default:
	}
}

func TestForwardForceCloseActiveStreamAndUpgrade(t *testing.T) {
	for _, path := range []string{"/stream", "/upgrade"} {
		t.Run(path, func(t *testing.T) {
			upstreamDone := make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				if r.URL.Path == "/stream" {
					w.Write([]byte("first\n"))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
				rw.Flush()
				io.Copy(conn, rw)
			}))
			defer backend.Close()
			n, events := forwardNode(t, &forwardGuest{address: strings.TrimPrefix(backend.URL, "http://")})
			addr, client, cleanup := localForwardTLS(t, n)
			defer cleanup()
			var inbound net.Conn
			var stream io.ReadCloser
			if path == "/stream" {
				res, err := client.Get("https://example.com/stream")
				if err != nil {
					t.Fatal(err)
				}
				stream = res.Body
				defer stream.Close()
				if line, err := bufio.NewReader(stream).ReadString('\n'); err != nil || line != "first\n" {
					t.Fatalf("%q %v", line, err)
				}
			} else {
				conn, err := tls.Dial("tcp", addr, client.Transport.(*http.Transport).TLSClientConfig.Clone())
				if err != nil {
					t.Fatal(err)
				}
				inbound = conn
				defer conn.Close()
				fmt.Fprint(conn, "GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
				if err != nil || response.StatusCode != 101 {
					t.Fatalf("%v %v", response, err)
				}
				fmt.Fprint(conn, "ping\n")
				if line, err := reader.ReadString('\n'); err != nil || line != "ping\n" {
					t.Fatalf("%q %v", line, err)
				}
			}
			n.cancel()
			joined := make(chan struct{})
			go func() { cleanup(); n.relays.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(5 * time.Second):
				t.Fatal("force-close did not join HTTP owner")
			}
			select {
			case <-upstreamDone:
			case <-time.After(5 * time.Second):
				t.Fatal("guest upgraded/stream socket survived")
			}
			if inbound != nil {
				inbound.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := inbound.Read(make([]byte, 1)); err == nil {
					t.Fatal("upgraded client survived")
				}
			}
			if stream != nil {
				if _, err := stream.Read(make([]byte, 1)); err == nil {
					t.Fatal("streaming client survived")
				}
			}
			select {
			case e := <-events:
				if e.Decision != "allow" || e.Reason != "connected" {
					t.Fatalf("%+v", e)
				}
			default:
				t.Fatal("force-close joined before audit")
			}
		})
	}
}

func TestForwardProductionTLSFailureNeverContactsGuest(t *testing.T) {
	guest := &forwardGuest{address: "127.0.0.1:1"}
	n, events := forwardNode(t, guest)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &admissionListener{Listener: raw, node: n, forward: policy.Forward{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS}}
	cleanup := n.serveHTTPS(n.ctx, listener)
	defer cleanup()
	for _, name := range []string{"127.0.0.1", "attacker.example", "example.com"} {
		// IP ServerName suppresses SNI in the real Go TLS client. No test CA,
		// insecure verification, or replacement certificate issuer is involved.
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", raw.Addr().String(), &tls.Config{ServerName: name})
		if c != nil {
			c.Close()
		}
		if err == nil {
			t.Fatalf("certificate unexpectedly issued for %q", name)
		}
	}
	n.cancel()
	cleanup()
	n.relays.Wait()
	if guest.calls.Load() != 0 {
		t.Fatal("TLS failure contacted guest")
	}
	missingName := false
	for len(events) != 0 {
		e := <-events
		if e.Decision != "deny" {
			t.Fatalf("%+v", e)
		}
		if e.Reason == "tls_name_mismatch" {
			missingName = true
		}
	}
	if !missingName {
		t.Fatal("missing SNI was not classified")
	}
}

func TestForwardRawCleanupWhileNodeContextActive(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	n, events := forwardNode(t, &forwardGuest{address: backend.Addr().String()})
	client, raw := socketPair(t)
	defer client.Close()
	c := n.admit(raw, InboundEvent{Forward: "raw", Protocol: "tcp", Decision: "deny"}, "")
	relayDone := make(chan struct{})
	go func() { defer close(relayDone); defer c.Close(); n.relayGuest(c, 8080) }()
	guest, err := backend.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	n.closeForwardConnections("raw")
	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("forward cleanup waited on uncanceled node root")
	}
	n.relays.Wait()
	if n.ctx.Err() != nil {
		t.Fatal("forward cleanup canceled ordinary node networking")
	}
	guest.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := guest.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("raw guest socket survived cleanup: %v", err)
	}
	select {
	case <-events:
	default:
		t.Fatal("raw cleanup joined before audit")
	}
}

func TestForwardCompletedTLSWithoutHTTPIsNotGuestContact(t *testing.T) {
	guest := &forwardGuest{address: "127.0.0.1:1"}
	n, events := forwardNode(t, guest)
	addr, client, cleanup := localForwardTLS(t, n)
	defer cleanup()
	conn, err := tls.Dial("tcp", addr, client.Transport.(*http.Transport).TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if guest.calls.Load() != 0 {
		t.Fatal("handshake contacted guest")
	}
	select {
	case e := <-events:
		if e.Decision != "deny" || e.Reason != "guest_not_contacted" {
			t.Fatalf("%+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing terminal TLS event after client close")
	}
	n.relays.Wait()
}

func TestForwardHTTPSHostAuthorityPortRules(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
		want bool
	}{
		{"web.tail.ts.net", 443, true}, {"WEB.TAIL.TS.NET.", 443, true},
		{"web.tail.ts.net:443", 443, true}, {"web.tail.ts.net:9443", 9443, true},
		{"web.tail.ts.net", 9443, false}, {"web.tail.ts.net:443", 9443, false},
		{"web.tail.ts.net:09443", 9443, false}, {"other.tail.ts.net:9443", 9443, false},
		{"web.tail.ts.net.attacker:9443", 9443, false}, {"web.tail.ts.net..:443", 443, false},
		{"127.0.0.1:443", 443, false}, {"", 443, false},
	} {
		if got := forwardHost(tc.host, "web.tail.ts.net", tc.port); got != tc.want {
			t.Fatalf("%q port %d: %v", tc.host, tc.port, got)
		}
	}
}
