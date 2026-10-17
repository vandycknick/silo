package netnode

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// This adapter uses the same interface-address gonet dial as VirtualNetwork.
// The virtualnetwork regression separately exercises that concrete adapter and
// fail-closed reservations; this test drives the configured listener owner.
type forwardGvisorGuest struct {
	stack   *stack.Stack
	address tcpip.Address
}

func (g forwardGvisorGuest) DialGuest(ctx context.Context, port uint16) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, g.stack, tcpip.FullAddress{NIC: 1, Addr: g.address, Port: port}, ipv4.ProtocolNumber)
}
func TestForwardConfiguredTCPRealGvisorGuestIsolation(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer s.Close()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	attached := tcpip.AddrFrom4([4]byte{192, 168, 127, 2})
	other := tcpip.AddrFrom4([4]byte{192, 168, 127, 3})
	for _, address := range []tcpip.Address{attached, other} {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: address.WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	listenGuest := func(address tcpip.Address, port uint16) net.Listener {
		t.Helper()
		l, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: address, Port: port}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	backend := listenGuest(attached, 8080)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		payload, _ := io.ReadAll(c)
		c.Write(append([]byte("guest:"), payload...))
		c.(*gonet.TCPConn).CloseWrite()
	}()
	var decoys []net.Listener
	contacts := make(chan bool, 2)
	for _, addressPort := range []struct {
		address tcpip.Address
		port    uint16
	}{{attached, 18080}, {other, 8080}} {
		l := listenGuest(addressPort.address, addressPort.port)
		decoys = append(decoys, l)
		go func() {
			c, err := l.Accept()
			if err != nil {
				contacts <- false
				return
			}
			c.Close()
			contacts <- true
		}()
	}
	n, events := forwardNode(t, forwardGvisorGuest{stack: s, address: attached})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &admissionListener{Listener: raw, node: n, forward: policy.Forward{Name: "raw", ListenPort: 18080, GuestPort: 8080, Protocol: policy.ForwardProtocolTCP}}
	cleanup := n.serveTCP(n.ctx, listener)
	defer cleanup()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	client.Write([]byte("unaltered\x00bytes"))
	client.(*net.TCPConn).CloseWrite()
	payload, err := io.ReadAll(client)
	if err != nil || string(payload) != "guest:unaltered\x00bytes" {
		t.Fatalf("real guest response %q: %v", payload, err)
	}
	<-done
	cleanup()
	n.relays.Wait()
	if e := <-events; e.Port != 18080 || e.TargetPort != 8080 || e.Forward != "raw" || e.Decision != "allow" {
		t.Fatalf("%+v", e)
	}
	for _, l := range decoys {
		l.Close()
	}
	for range 2 {
		if <-contacts {
			t.Fatal("configured self forward contacted a different guest or same-port decoy")
		}
	}
}
