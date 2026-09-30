package packet

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestActualGvisorSelectedUDPTunnelIsRejectedAndAudited(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol}})
	defer s.Close()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	guest := tcpip.AddrFrom4([4]byte{192, 168, 127, 2})
	tail := tcpip.AddrFrom4([4]byte{100, 64, 0, 9})
	for _, addr := range []tcpip.Address{guest, tail} {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	p, err := policy.LoadReader("udp.json", strings.NewReader(`{"version":1,"tailscale":[{"name":"vm"}],"endpoints":[{"name":"tail","kind":"ip","family":"ip","transport":"packet-filter","tls":"none","destination_cidrs":["100.64.0.0/10"],"protocol":"udp"}],"rules":[{"endpoints":["tail"],"tunnel":"vm","verdict":"allow"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log := audit.New(file, p.PolicyHash())
	defer log.Close()
	route := router.New(p, log)
	flows := NewFlowTracker()
	var lock sync.Mutex
	forwarder := UDP(context.Background(), s, map[tcpip.Address]tcpip.Address{}, &lock, false, route, flows, TCPMetadata{VMID: "vm", RunID: "run", NetworkID: "net"})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, forwarder.HandlePacket)
	conn, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: guest, Port: 12345}, &tcpip.FullAddress{NIC: 1, Addr: tail, Port: 18080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("no host escape")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			var event audit.Event
			if err := json.Unmarshal(body, &event); err != nil {
				t.Fatal(err)
			}
			if event.Reason != "tunnel_error" || event.Tunnel == nil || event.Tunnel.Name != "vm" || event.DestIP != net.IP(tail.AsSlice()).String() {
				t.Fatalf("%+v", event)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing selected-UDP audit")
		}
		time.Sleep(time.Millisecond)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("UDP tunnel delivered data")
	}
}

func TestActualGvisorTailnetNATCannotEscapeToHostTCP(t *testing.T) {
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	port := uint16(host.Addr().(*net.TCPAddr).Port)
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer s.Close()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	guest := tcpip.AddrFrom4([4]byte{192, 168, 127, 2})
	tail := tcpip.AddrFrom4([4]byte{100, 64, 0, 9})
	for _, addr := range []tcpip.Address{guest, tail} {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	p, err := policy.LoadReader("tcp.json", strings.NewReader(`{"version":1,"settings":{"default_action":"allow"},"tailscale":[{"name":"vm"}],"endpoints":[{"name":"tail","kind":"ip","family":"ip","transport":"packet-filter","tls":"none","destination_cidrs":["100.64.0.0/10"],"protocol":"tcp"}],"rules":[{"endpoints":["tail"],"tunnel":"vm","verdict":"allow"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log := audit.New(file, p.PolicyHash())
	defer log.Close()
	route := router.New(p, log)
	flows := NewFlowTracker()
	var lock sync.Mutex
	forwarder := TCP(context.Background(), s, map[tcpip.Address]tcpip.Address{tail: tcpip.AddrFrom4([4]byte{127, 0, 0, 1})}, &lock, false, route, NewTCPDispatcher(), flows, TCPMetadata{})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tail, Port: port}, ipv4.ProtocolNumber)
	if err == nil {
		conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write([]byte("no escape"))
		conn.Read(make([]byte, 1))
		conn.Close()
	}
	deadline := time.Now().Add(time.Second)
	for {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			var event audit.Event
			if err = json.Unmarshal(body, &event); err != nil {
				t.Fatal(err)
			}
			if event.Reason != "tunnel_not_connected" || event.DestIP != "100.64.0.9" || event.Tunnel == nil {
				t.Fatalf("%+v", event)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing original tailnet destination audit")
		}
		time.Sleep(time.Millisecond)
	}
	host.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if conn, err := host.Accept(); err == nil {
		conn.Close()
		t.Fatal("tailnet NAT escaped to a listening host TCP socket")
	}
}
