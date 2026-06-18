package virtualnetwork

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	upstreamForwarder "github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/forwarder"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Metadata struct {
	VMID      string
	NetworkID string
}

type VirtualNetwork struct {
	configuration *types.Configuration
	stack         *stack.Stack
	networkSwitch *tap.Switch
	servicesMux   http.Handler
	ipPool        *tap.IPPool
}

func New(configuration *types.Configuration, route *router.Router, httpProxy *forwarder.HTTPProxy, httpsProxy *forwarder.HTTPSProxy, metadata Metadata) (*VirtualNetwork, error) {
	_, subnet, err := net.ParseCIDR(configuration.Subnet)
	if err != nil {
		return nil, fmt.Errorf("cannot parse subnet cidr: %w", err)
	}

	ipPool := tap.NewIPPool(subnet)
	ipPool.Reserve(net.ParseIP(configuration.GatewayIP), configuration.GatewayMacAddress)
	for ip, mac := range configuration.DHCPStaticLeases {
		ipPool.Reserve(net.ParseIP(ip), mac)
	}

	mtu := configuration.MTU
	if mtu < 0 || mtu > math.MaxInt32 {
		return nil, errors.New("mtu is out of range")
	}
	tapEndpoint, err := tap.NewLinkEndpoint(configuration.Debug, uint32(mtu), configuration.GatewayMacAddress, configuration.GatewayIP, configuration.GatewayVirtualIPs)
	if err != nil {
		return nil, fmt.Errorf("cannot create tap endpoint: %w", err)
	}
	networkSwitch := tap.NewSwitch(configuration.Debug)
	tapEndpoint.Connect(networkSwitch)
	networkSwitch.Connect(tapEndpoint)

	var endpoint stack.LinkEndpoint = tapEndpoint
	if configuration.CaptureFile != "" {
		_ = os.Remove(configuration.CaptureFile)
		fd, err := os.Create(configuration.CaptureFile)
		if err != nil {
			return nil, fmt.Errorf("cannot create capture file: %w", err)
		}
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, fd, math.MaxUint32)
		if err != nil {
			return nil, fmt.Errorf("cannot create sniffer: %w", err)
		}
	}

	stack, err := createStack(configuration, endpoint)
	if err != nil {
		return nil, fmt.Errorf("cannot create network stack: %w", err)
	}

	mux, err := addServices(configuration, stack, ipPool, route, httpProxy, httpsProxy, metadata)
	if err != nil {
		return nil, fmt.Errorf("cannot add network services: %w", err)
	}

	return &VirtualNetwork{configuration: configuration, stack: stack, networkSwitch: networkSwitch, servicesMux: mux, ipPool: ipPool}, nil
}

func (n *VirtualNetwork) AcceptVfkit(ctx context.Context, conn net.Conn) error {
	return n.networkSwitch.Accept(ctx, conn, types.VfkitProtocol)
}

func addServices(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool, route *router.Router, httpProxy *forwarder.HTTPProxy, httpsProxy *forwarder.HTTPSProxy, metadata Metadata) (http.Handler, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := forwarder.TCP(s, translation, &natLock, configuration.Ec2MetadataAccess, route, httpProxy, httpsProxy, forwarder.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(s, translation, &natLock, configuration.Ec2MetadataAccess, route, forwarder.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	icmpForwarder := upstreamForwarder.ICMP(s, translation, &natLock)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)

	dnsMux, err := dnsServer(configuration, s)
	if err != nil {
		return nil, err
	}
	dhcpMux, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}
	forwarderMux, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/forwarder/", http.StripPrefix("/forwarder", forwarderMux))
	mux.Handle("/dhcp/", http.StripPrefix("/dhcp", dhcpMux))
	mux.Handle("/dns/", http.StripPrefix("/dns", dnsMux))
	return mux, nil
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func dnsServer(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	tcpLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	server, err := dns.New(udpConn, tcpLn, configuration.DNS)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := server.Serve(); err != nil {
			slog.Error("dns udp server stopped", "error", err)
		}
	}()
	go func() {
		if err := server.ServeTCP(); err != nil {
			slog.Error("dns tcp server stopped", "error", err)
		}
	}()
	return server.Mux(), nil
}

func dhcpServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (http.Handler, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := server.Serve(); err != nil {
			slog.Error("dhcp server stopped", "error", err)
		}
	}()
	return server.Mux(), nil
}

func forwardHostVM(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
	fw := upstreamForwarder.NewPortsForwarder(s)
	for local, remote := range configuration.Forwards {
		if strings.HasPrefix(local, "udp:") {
			if err := fw.Expose(types.UDP, strings.TrimPrefix(local, "udp:"), remote); err != nil {
				return nil, err
			}
		} else if err := fw.Expose(types.TCP, local, remote); err != nil {
			return nil, err
		}
	}
	return fw.Mux(), nil
}

func createStack(configuration *types.Configuration, endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4}})
	if err := s.CreateNIC(1, endpoint); err != nil {
		return nil, errors.New(err.String())
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	_, parsedSubnet, err := net.ParseCIDR(configuration.Subnet)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cidr: %w", err)
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	if err != nil {
		return nil, fmt.Errorf("cannot parse subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: tcpip.Address{}, NIC: 1}})
	return s, nil
}
