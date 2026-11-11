package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/wire"
)

func TestConnectionCountsPerIP(t *testing.T) {
	var counts connectionCounts
	ip := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	for range maxConnectionsPerIP {
		if !counts.acquire(ip) {
			t.Fatal("per-IP limit reached too soon")
		}
	}
	if counts.acquire(ip) || counts.acquire(mapped) {
		t.Fatal("per-IP cap bypassed, including IPv4-mapped address")
	}
	other := netip.MustParseAddr("2001:db8::1")
	if !counts.acquire(other) {
		t.Fatal("one IP exhausted another IP's admission slots")
	}
	counts.release(mapped)
	if !counts.acquire(ip) || counts.acquire(ip) {
		t.Fatal("released per-IP slot was not reused exactly once")
	}
	for range maxConnectionsPerIP {
		counts.release(ip)
	}
	counts.release(other)
	if counts.total != 0 || len(counts.perIP) != 0 {
		t.Fatalf("connection accounting leaked: %+v", counts)
	}
}

func TestConnectionCountsGlobal(t *testing.T) {
	var counts connectionCounts
	var admitted []netip.Addr
	ip := netip.MustParseAddr("2001:db8::1")
	for range maxConnections {
		if !counts.acquire(ip) {
			t.Fatal("global limit reached too soon")
		}
		admitted = append(admitted, ip)
		ip = ip.Next()
	}
	if counts.acquire(ip) {
		t.Fatal("global cap bypassed by a new IP")
	}
	counts.release(admitted[0])
	if !counts.acquire(ip) || counts.acquire(ip.Next()) {
		t.Fatal("released global slot was not reused exactly once")
	}
	for _, addr := range admitted[1:] {
		counts.release(addr)
	}
	counts.release(ip)
	if counts.total != 0 || len(counts.perIP) != 0 {
		t.Fatalf("connection accounting leaked: %+v", counts)
	}
}

func startAcceptSession(t *testing.T) (*session, *owner, []net.Listener) {
	t.Helper()
	a, b, err := wire.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	o := &owner{conn: a, reader: &wire.Reader{Conn: a}}
	s := &session{writer: &wire.Writer{Conn: b}, streams: make(map[net.Conn]struct{})}
	acceptDone := make(chan struct{}, 2)
	t.Cleanup(func() {
		listenerCount := len(s.listeners)
		s.stopListeners()
		a.Close()
		b.Close()
		o.reader.Close()
		s.mu.Lock()
		for conn := range s.streams {
			conn.Close()
		}
		s.mu.Unlock()
		done := make(chan struct{})
		go func() {
			for range listenerCount {
				<-acceptDone
			}
			s.copies.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("accept session did not stop")
		}
	})
	for _, name := range []string{"ssh", "http"} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s.listeners = append(s.listeners, l)
		go func() {
			s.accept(context.Background(), l, name)
			acceptDone <- struct{}{}
		}()
	}
	if err := a.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return s, o, s.listeners
}

func dialListener(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func waitConnectionCount(t *testing.T, s *session, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		got := s.connections.total
		s.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection count = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAcceptConnectionCapSharedAcrossListeners(t *testing.T) {
	s, o, listeners := startAcceptSession(t)
	var peers []net.Conn
	var streams []*net.UnixConn
	for i := range maxConnectionsPerIP {
		peers = append(peers, dialListener(t, listeners[i%len(listeners)]))
		meta, stream := o.connection(t)
		if want := []string{"ssh", "http"}[i%len(listeners)]; meta.Listener != want {
			t.Fatalf("listener = %q, want %q", meta.Listener, want)
		}
		streams = append(streams, stream)
	}
	for _, listener := range listeners {
		rejected := dialListener(t, listener)
		if _, err := rejected.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("excess connection not closed: %v", err)
		}
	}
	if err := o.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	m, fd, err := o.reader.Receive()
	if fd != nil {
		fd.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("excess connection sent a frame: %T, fd=%v, err=%v", m, fd, err)
	}
	if err := o.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	peers[0].Close()
	streams[0].Close()
	waitConnectionCount(t, s, maxConnectionsPerIP-1)
	replacementPeer := dialListener(t, listeners[1])
	_, replacement := o.connection(t)
	if _, err := replacement.Write([]byte("slot reused")); err != nil {
		t.Fatal(err)
	}
	waitConnectionCount(t, s, maxConnectionsPerIP)
	for i := range peers {
		peers[i].Close()
		streams[i].Close()
	}
	replacement.Close()
	replacementPeer.Close()
	waitConnectionCount(t, s, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections.perIP) != 0 || len(s.streams) != 0 {
		t.Fatal("completed relays retained connection state")
	}
}

func TestAcceptFailedHandoffReleasesSlot(t *testing.T) {
	s, o, listeners := startAcceptSession(t)
	o.conn.Close()
	conn := dialListener(t, listeners[0])
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed handoff did not close peer: %v", err)
	}
	waitConnectionCount(t, s, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections.perIP) != 0 || len(s.streams) != 0 {
		t.Fatal("failed handoff retained connection state")
	}
}
