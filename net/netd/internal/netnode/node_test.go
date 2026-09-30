package netnode

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
)

func TestDNSClassificationProvenanceAndInvalidation(t *testing.T) {
	n := newTestNode(t, Options{})
	status := &ipnstate.Status{BackendState: "Running", CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "tail.test"}, Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {DNSName: "peer.tail.test."},
		key.NewNode().Public(): {DNSName: "duplicate.one.tail.test."},
		key.NewNode().Public(): {DNSName: "duplicate.two.tail.test."},
	}}
	n.observe(status)
	for _, tc := range []struct {
		name, canonical string
		classified      bool
	}{{"peer", "peer.tail.test", true}, {"duplicate", "", true}, {"box.tail.test.", "box.tail.test", true}, {"box.tail123.ts.net.", "", true}, {"public.example", "public.example", false}, {"tail.test.attacker.example", "tail.test.attacker.example", false}} {
		name, classified := n.DNSName(tc.name)
		if name != tc.canonical || classified != tc.classified {
			t.Fatalf("%s: %q %t", tc.name, name, classified)
		}
	}
	ip := netip.MustParseAddr("10.0.0.9")
	msg := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "peer.tail.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 3600}, A: net.ParseIP(ip.String())}}}
	n.remember(msg, n.fingerprint)
	if !n.IsDestination(ip) || msg.Answer[0].Header().Ttl != 60 {
		t.Fatal("missing bounded provenance")
	}
	n.mu.Lock()
	n.provenance[ip] = time.Now().Add(-time.Second)
	n.mu.Unlock()
	if n.IsDestination(ip) {
		t.Fatal("expired provenance retained")
	}
	n.remember(msg, n.fingerprint)
	n.observe(nil)
	for _, name := range []string{"peer", "box.tail.test.", "peer.tail123.ts.net."} {
		canonical, classified := n.DNSName(name)
		if !classified || canonical != "" {
			t.Fatalf("disconnected DNS classification escaped: %q %q %t", name, canonical, classified)
		}
	}
	if len(n.provenance) != 0 || !n.IsDestination(ip) {
		t.Fatal("positive provenance was not invalidated, or cached address escaped classification")
	}
	if n.remember(msg, "stale fingerprint") {
		t.Fatal("stale DNS answer was accepted")
	}
	n.mu.Lock()
	n.quarantined[ip] = time.Now().Add(-time.Second)
	n.mu.Unlock()
	if n.IsDestination(ip) {
		t.Fatal("expired quarantine retained")
	}
	for _, text := range []string{"100.64.0.1", "100.127.255.255", "fd7a:115c:a1e0::123"} {
		if !n.IsDestination(netip.MustParseAddr(text)) {
			t.Fatal(text)
		}
	}
}

func TestActualUnregisteredNodeStrictAdapterCannotReachHostListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := &tsnet.Server{Dir: t.TempDir(), Hostname: "silo-offline-adapter", ControlURL: "http://127.0.0.1:1", UserLogf: t.Logf}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dial, err := strictDialer(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := dial(ctx, netip.MustParseAddrPort(listener.Addr().String()))
	if err == nil {
		conn.Close()
		t.Fatal("strict netstack reached host listener")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("host fallback accepted")
	}
	if _, err := strictDialer(&tsnet.Server{}); err == nil {
		t.Fatal("uninitialized adapter accepted")
	}
}

func TestDNSProvenanceCapacityIsAtomicAndQuarantineExpires(t *testing.T) {
	n := newTestNode(t, Options{})
	n.observe(&ipnstate.Status{BackendState: "Running"})
	msg := &dns.Msg{}
	for i := 0; i < 4096; i++ {
		msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: "peer.tail.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.IPv4(10, byte(i>>8), byte(i), 1)})
	}
	if !n.remember(msg, n.fingerprint) {
		t.Fatal("valid capacity-sized answer rejected")
	}
	extra := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "peer.tail.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}}
	if n.remember(extra, n.fingerprint) || n.IsDestination(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("capacity-exhausted DNS answer partially committed")
	}
	n.observe(nil)
	if len(n.provenance) != 0 || len(n.quarantined) != 4096 || !n.IsDestination(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("invalidation exposed cached guest addresses to direct routing")
	}
	n.mu.Lock()
	for ip := range n.quarantined {
		n.quarantined[ip] = time.Now().Add(-time.Second)
	}
	n.mu.Unlock()
	if n.IsDestination(netip.MustParseAddr("10.0.0.1")) || len(n.quarantined) != 0 {
		t.Fatal("quarantine exceeded TTL")
	}
	n.observe(&ipnstate.Status{BackendState: "Running"})
	if !n.remember(extra, n.fingerprint) {
		t.Fatal("expired quarantine retained capacity")
	}
	alias := &dns.Msg{Answer: []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "peer.tail.test.", Rrtype: dns.TypeCNAME, Class: 1, Ttl: 60}, Target: "public.example."}}}
	if n.remember(alias, n.fingerprint) {
		t.Fatal("classified DNS alias escaped to public DNS")
	}
}

func TestActualNodeStartCloseOwnershipAndDisconnectedDial(t *testing.T) {
	for i := 0; i < 5; i++ {
		n := newTestNode(t, Options{Dir: t.TempDir(), Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "offline-owner", ControlURL: "http://127.0.0.1:1"}})
		n.Start(context.Background())
		_, reason, err := n.DialTCP(context.Background(), netip.MustParseAddrPort("100.64.0.1:80"))
		if err == nil || reason != "tunnel_not_connected" {
			t.Fatalf("%s %v", reason, err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = n.Close() }()
		go func() { defer wg.Done(); n.Start(context.Background()); _ = n.Close() }()
		wg.Wait()
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*net.TCPConn{client, server} {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		t.Cleanup(func() { c.Close() })
	}
	return client, server
}
func TestRealTCPRelayHalfCloseAndCancellation(t *testing.T) {
	a, in := tcpPair(t)
	out, b := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Relay(ctx, in, out); close(done) }()
	a.Write([]byte("request"))
	a.CloseWrite()
	data, err := io.ReadAll(b)
	if err != nil || string(data) != "request" {
		t.Fatalf("%q %v", data, err)
	}
	b.Write([]byte("response"))
	b.CloseWrite()
	data, err = io.ReadAll(a)
	if err != nil || string(data) != "response" {
		t.Fatalf("%q %v", data, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay failed to join")
	}
	a, in = tcpPair(t)
	out, b = tcpPair(t)
	done = make(chan struct{})
	go func() { Relay(ctx, in, out); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel failed to join")
	}
}

// Real tailnet qualification, never replaced by a fake control plane.
func TestRealTailnetStrictDialDNSAndPersistentIdentity(t *testing.T) {
	secret, suffix := os.Getenv("SILO_E2E_TS_CLIENT_SECRET"), os.Getenv("SILO_E2E_TS_TAILNET")
	if secret == "" || suffix == "" {
		t.Skip("requires SILO_E2E_TS_CLIENT_SECRET and SILO_E2E_TS_TAILNET; no tailnet qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	hostname := "silo-s8-" + strings.ToLower(time.Now().Format("150405.000000"))
	hostname = strings.ReplaceAll(hostname, ".", "-")
	newServer := func(dir, name string) *tsnet.Server {
		return &tsnet.Server{Dir: dir, Hostname: name, AuthKey: mintEnrollmentKey(t, ctx, secret), AdvertiseTags: []string{"tag:silo-test-vm"}, ControlURL: os.Getenv("SILO_E2E_TS_CONTROL_URL"), UserLogf: t.Logf}
	}
	newNode := func(source credentials.Source) *Node {
		return newTestNode(t, Options{Dir: dir, Declaration: policy.TailscaleDecl{Name: "vm", Hostname: hostname, Tags: []string{"tag:silo-test-vm"}, ControlURL: os.Getenv("SILO_E2E_TS_CONTROL_URL")}, Secrets: source})
	}
	waitRunning := func(n *Node) *ipnstate.Status {
		for ctx.Err() == nil {
			n.mu.Lock()
			ready, client := n.running && n.dial != nil, n.client
			n.mu.Unlock()
			if ready && client != nil {
				bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
				status, err := client.Status(bounded)
				cancel()
				if err == nil && status.BackendState == "Running" {
					return status
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
		t.Fatal("actual node did not reach Running")
		return nil
	}
	n := newNode(credentials.NewStatic(map[string][]byte{"vm.tailscale.auth_key": []byte(mintEnrollmentKey(t, ctx, secret))}, nil))
	n.Start(ctx)
	defer func() { n.Close() }()
	first := waitRunning(n)
	if first.Self == nil {
		t.Fatal("missing identity")
	}
	id := first.Self.ID
	peer := newServer(t.TempDir(), hostname+"-peer")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ps, err := peer.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := peer.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); conn.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(conn, conn) }()
		}
	}()
	if ps.Self == nil || len(ps.Self.TailscaleIPs) == 0 {
		t.Fatal("missing actual peer addresses")
	}
	for ctx.Err() == nil {
		if full, ok := n.DNSName(hostname + "-peer"); ok && full != "" {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	conn, _, err := n.DialTCP(ctx, netip.AddrPortFrom(ps.Self.TailscaleIPs[0], 8080))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("s8"))
	got := make([]byte, 2)
	_, err = io.ReadFull(conn, got)
	conn.Close()
	if err != nil || string(got) != "s8" {
		t.Fatalf("%q %v", got, err)
	}
	answer, err := n.QueryDNS(ctx, ps.Self.DNSName, dns.TypeA)
	if err != nil || answer == nil || len(answer.Answer) == 0 {
		t.Fatalf("DNS %v %v", answer, err)
	}
	answer, err = n.QueryDNS(ctx, hostname+"-peer", dns.TypeA)
	if err != nil || answer == nil || len(answer.Answer) == 0 {
		t.Fatalf("short DNS %v %v", answer, err)
	}
	if !strings.HasSuffix(strings.TrimSuffix(ps.Self.DNSName, "."), suffix) {
		t.Fatal("unexpected test tailnet")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n = newNode(nil)
	n.Start(ctx)
	restarted := waitRunning(n)
	if restarted.Self == nil || restarted.Self.ID != id {
		t.Fatalf("identity %v", restarted)
	}
}

func newTestNode(t *testing.T, o Options) *Node {
	t.Helper()
	n, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRejectDiscoveryKeysBeforeServerConstructionAndOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, key := range []string{"tskey-client-sensitive?baseURL=http://" + listener.Addr().String(), "tskey-client-sensitive", "tskey-api-sensitive", "eyJhbGciOiJ-sensitive-jwt", "file:/private/wif", "tskey-auth-sensitive?baseURL=http://" + listener.Addr().String(), "tskey-auth-", "tskey-auth-sensitive\n"} {
		dir := t.TempDir()
		started := time.Now()
		n, err := New(Options{Dir: dir, Declaration: policy.TailscaleDecl{Name: "vm", Tags: []string{"tag:silo-test-vm"}}, Secrets: credentials.NewStatic(map[string][]byte{"vm.tailscale.auth_key": []byte(key)}, nil)})
		if err == nil || n != nil {
			t.Fatal("credential discovery was not rejected before construction")
		}
		if strings.Contains(err.Error(), "sensitive") || time.Since(started) > time.Second {
			t.Fatal("rejection leaked material or was not bounded")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected key initialized node state")
		}
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("rejected key made an outbound OAuth connection")
	}
	for _, key := range []string{"", "tskey-auth-synthetic-literal_key"} {
		n := newTestNode(t, Options{Dir: t.TempDir(), Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "literal-key-close", ControlURL: "http://127.0.0.1:1"}, Secrets: credentials.NewStatic(map[string][]byte{"vm.tailscale.auth_key": []byte(key)}, nil)})
		n.Start(context.Background())
		deadline := time.Now().Add(2 * time.Second)
		for {
			n.mu.Lock()
			initialized := n.initialized
			n.mu.Unlock()
			if initialized {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("literal enrollment key did not initialize within budget")
			}
			time.Sleep(time.Millisecond)
		}
		done := make(chan error, 1)
		go func() { done <- n.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("literal-key initialization/Close exceeded budget")
		}
	}
}
