package virtualnetwork

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/netnode"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestActualGvisorGuestDialAndFallbackAdmission(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer s.Close()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.AddrFrom4([4]byte{192, 168, 127, 2})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	guest := &VirtualNetwork{stack: s, configuration: &types.Configuration{DeviceIP: "192.168.127.2"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := guest.DialGuest(ctx, 8080); err == nil {
		t.Fatal("unattached guest accepted")
	}
	guest.attached.Store(true)
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: addr, Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			data, _ := io.ReadAll(c)
			c.Write(append([]byte("reply:"), data...))
			c.(*gonet.TCPConn).CloseWrite()
		}
	}()
	events := make(chan netnode.InboundEvent, 260)
	flows := packet.NewFlowTracker()
	node, err := netnode.New(netnode.Options{Dir: t.TempDir(), Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "silo-offline-guest", ControlURL: "http://127.0.0.1:1"}, Guest: guest, Flows: flows, Audit: func(e netnode.InboundEvent) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	node.Start(ctx)
	defer node.Close()
	for _, tc := range []struct {
		port uint16
		want string
	}{{8080, "connected"}, {22, "ssh_reserved"}, {8081, "guest_connection_failed"}} {
		// A real host TCP leg carries the production fallback handler into gonet.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		in, err := listener.Accept()
		listener.Close()
		if err != nil {
			t.Fatal(err)
		}
		handler, intercept := node.Fallback(netip.MustParseAddrPort("100.64.0.9:1234"), netip.AddrPortFrom(netip.MustParseAddr("100.64.0.2"), tc.port))
		if !intercept {
			t.Fatal("not intercepted")
		}
		go handler(in)
		client.SetDeadline(time.Now().Add(2 * time.Second))
		if tc.port == 8080 {
			client.Write([]byte("payload"))
			client.(*net.TCPConn).CloseWrite()
			data, err := io.ReadAll(client)
			if err != nil || string(data) != "reply:payload" {
				t.Fatalf("%q %v", data, err)
			}
		} else {
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("denied connection stayed open")
			}
		}
		client.Close()
		select {
		case e := <-events:
			if e.Reason != tc.want || e.Port != tc.port {
				t.Fatalf("%+v", e)
			}
		case <-ctx.Done():
			t.Fatal("missing audit")
		}
	}
	// Hold 256 real guest connections, then prove admission rejects the 257th.
	held, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: addr, Port: 8082}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	accepted := make(chan struct{}, 256)
	var guestWorkers sync.WaitGroup
	go func() {
		for i := 0; i < 256; i++ {
			conn, err := held.Accept()
			if err != nil {
				return
			}
			guestWorkers.Add(1)
			go func() { defer guestWorkers.Done(); defer conn.Close(); io.Copy(io.Discard, conn) }()
			accepted <- struct{}{}
		}
	}()
	for i := 0; i < 257; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		in, err := listener.Accept()
		listener.Close()
		if err != nil {
			t.Fatal(err)
		}
		handler, _ := node.Fallback(netip.MustParseAddrPort("100.64.0.9:1234"), netip.MustParseAddrPort("100.64.0.2:8082"))
		go handler(in)
		if i < 256 {
			select {
			case <-accepted:
			case <-ctx.Done():
				t.Fatal("guest admission timed out")
			}
		} else {
			client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("257th connection accepted")
			}
			select {
			case e := <-events:
				if e.Reason != "connection_limit" {
					t.Fatalf("%+v", e)
				}
			case <-ctx.Done():
				t.Fatal("missing limit audit")
			}
		}
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	guestWorkers.Wait()
	if err := flows.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		select {
		case e := <-events:
			if e.Reason != "connected" || e.Decision != "allow" {
				t.Fatalf("%+v", e)
			}
		default:
			t.Fatal("Close returned before relay audit completed")
		}
	}
}

func TestActualLocalDNSStaticZonesAndClassifiedFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, err := netnode.New(netnode.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := &gatewayDNS{ctx: ctx, node: node, slots: make(chan struct{}, 2), zones: []types.Zone{{Name: "containers.internal.", Records: []types.Record{{Name: "gateway", IP: net.IPv4(192, 168, 127, 1)}}}}}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: h}
	go server.ActivateAndServe()
	defer server.Shutdown()
	for _, tc := range []struct {
		name    string
		code    int
		answers int
	}{{"gateway.containers.internal.", dns.RcodeSuccess, 1}, {"missing.containers.internal.", dns.RcodeSuccess, 0}, {"peer.tail123.ts.net.", dns.RcodeServerFailure, 0}} {
		q := new(dns.Msg)
		q.SetQuestion(tc.name, dns.TypeA)
		answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, conn.LocalAddr().String())
		if err != nil || answer.Rcode != tc.code || len(answer.Answer) != tc.answers {
			t.Fatalf("%s %v %v", tc.name, answer, err)
		}
	}
}
