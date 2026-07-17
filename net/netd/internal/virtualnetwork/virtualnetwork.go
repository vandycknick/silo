package virtualnetwork

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	upstreamForwarder "github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"golang.org/x/sync/errgroup"
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
	services      []networkService
	ipPool        *tap.IPPool
	captureFile   *os.File
	closeOnce     sync.Once
	closed        atomic.Bool
	closeErr      error
}

type networkService struct {
	name  string
	serve func() error
	close func() error
}

func New(ctx context.Context, networkConfig *config.NetworkConfig, route *router.Router, dispatcher *packet.TCPDispatcher, flows *packet.FlowTracker, metadata Metadata) (*VirtualNetwork, error) {
	if networkConfig == nil {
		return nil, errors.New("network configuration is required")
	}
	configuration := upstreamConfiguration(networkConfig)
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
	var captureFile *os.File
	if configuration.CaptureFile != "" {
		_ = os.Remove(configuration.CaptureFile)
		fd, err := os.Create(configuration.CaptureFile)
		if err != nil {
			return nil, fmt.Errorf("cannot create capture file: %w", err)
		}
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, fd, math.MaxUint32)
		if err != nil {
			_ = fd.Close()
			return nil, fmt.Errorf("cannot create sniffer: %w", err)
		}
		captureFile = fd
	}

	stack, err := createStack(configuration, endpoint)
	if err != nil {
		if captureFile != nil {
			_ = captureFile.Close()
		}
		return nil, fmt.Errorf("cannot create network stack: %w", err)
	}

	mux, services, err := addServices(ctx, configuration, stack, ipPool, route, dispatcher, flows, metadata)
	if err != nil {
		stack.Close()
		if captureFile != nil {
			_ = captureFile.Close()
		}
		return nil, fmt.Errorf("cannot add network services: %w", err)
	}

	return &VirtualNetwork{configuration: configuration, stack: stack, networkSwitch: networkSwitch, servicesMux: mux, services: services, ipPool: ipPool, captureFile: captureFile}, nil
}

func upstreamConfiguration(configuration *config.NetworkConfig) *types.Configuration {
	zones := make([]types.Zone, 0, len(configuration.DNS))
	for _, zone := range configuration.DNS {
		records := make([]types.Record, 0, len(zone.Records))
		for _, record := range zone.Records {
			records = append(records, types.Record{Name: record.Name, IP: append(net.IP(nil), record.IP...)})
		}
		zones = append(zones, types.Zone{Name: zone.Name, Records: records})
	}
	return &types.Configuration{
		CaptureFile:       configuration.CaptureFile,
		Debug:             configuration.Debug,
		MTU:               configuration.MTU,
		Subnet:            configuration.Subnet,
		GatewayIP:         configuration.GatewayIP,
		DeviceIP:          configuration.DeviceIP,
		HostIP:            configuration.HostIP,
		GatewayMacAddress: configuration.GatewayMACAddress,
		DNS:               zones,
		DNSSearchDomains:  append([]string(nil), configuration.DNSSearchDomains...),
		Forwards:          cloneStringMap(configuration.Forwards),
		NAT:               cloneStringMap(configuration.NAT),
		GatewayVirtualIPs: append([]string(nil), configuration.GatewayVirtualIPs...),
		DHCPStaticLeases:  cloneStringMap(configuration.DHCPStaticLeases),
		Ec2MetadataAccess: configuration.EC2MetadataAccess,
		Protocol:          types.VfkitProtocol,
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func (n *VirtualNetwork) AcceptVfkit(ctx context.Context, conn net.Conn) error {
	return n.Run(ctx, conn)
}

func (n *VirtualNetwork) Run(ctx context.Context, conn net.Conn) error {
	if n == nil {
		return errors.New("virtual network is not configured")
	}
	if conn == nil {
		return errors.New("vfkit connection is nil")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, groupCtx := errgroup.WithContext(runCtx)
	for _, service := range n.services {
		service := service
		group.Go(func() error {
			defer cancel()
			err := service.serve()
			if n.closed.Load() || groupCtx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%s stopped: %w", service.name, err)
			}
			return fmt.Errorf("%s stopped unexpectedly", service.name)
		})
	}
	group.Go(func() error {
		defer cancel()
		err := n.networkSwitch.Accept(groupCtx, conn, types.VfkitProtocol)
		if n.closed.Load() || groupCtx.Err() != nil {
			return nil
		}
		return err
	})
	group.Go(func() error {
		<-groupCtx.Done()
		return n.Close()
	})
	return group.Wait()
}

func (n *VirtualNetwork) Close() error {
	if n == nil {
		return nil
	}
	n.closeOnce.Do(func() {
		n.closed.Store(true)
		for _, service := range n.services {
			if service.close != nil {
				n.closeErr = errors.Join(n.closeErr, service.close())
			}
		}
		if n.stack != nil {
			n.stack.Close()
		}
		if n.captureFile != nil {
			n.closeErr = errors.Join(n.closeErr, n.captureFile.Close())
		}
	})
	return n.closeErr
}

func addServices(ctx context.Context, configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool, route *router.Router, dispatcher *packet.TCPDispatcher, flows *packet.FlowTracker, metadata Metadata) (http.Handler, []networkService, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := packet.TCP(ctx, s, translation, &natLock, configuration.Ec2MetadataAccess, route, dispatcher, flows, packet.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := packet.UDP(ctx, s, translation, &natLock, configuration.Ec2MetadataAccess, route, flows, packet.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	icmpForwarder := upstreamForwarder.ICMP(s, translation, &natLock)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)

	dnsMux, dnsServices, err := dnsServer(configuration, s)
	if err != nil {
		return nil, nil, err
	}
	dhcpMux, dhcpService, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, nil, errors.Join(err, closeNetworkServices(dnsServices))
	}
	services := append(dnsServices, dhcpService)
	forwarderMux, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, nil, errors.Join(err, closeNetworkServices(services))
	}
	mux := http.NewServeMux()
	mux.Handle("/forwarder/", http.StripPrefix("/forwarder", forwarderMux))
	mux.Handle("/dhcp/", http.StripPrefix("/dhcp", dhcpMux))
	mux.Handle("/dns/", http.StripPrefix("/dns", dnsMux))
	return mux, services, nil
}

func closeNetworkServices(services []networkService) error {
	var closeErr error
	for _, service := range services {
		if service.close != nil {
			closeErr = errors.Join(closeErr, service.close())
		}
	}
	return closeErr
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func dnsServer(configuration *types.Configuration, s *stack.Stack) (http.Handler, []networkService, error) {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, nil, err
	}
	tcpLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, ipv4.ProtocolNumber)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	server, err := dns.New(udpConn, tcpLn, configuration.DNS)
	if err != nil {
		_ = udpConn.Close()
		_ = tcpLn.Close()
		return nil, nil, err
	}
	services := []networkService{
		{name: "dns udp server", serve: server.Serve, close: udpConn.Close},
		{name: "dns tcp server", serve: server.ServeTCP, close: tcpLn.Close},
	}
	return server.Mux(), services, nil
}

func dhcpServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (http.Handler, networkService, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return nil, networkService{}, err
	}
	return server.Mux(), networkService{name: "dhcp server", serve: server.Serve, close: server.Underlying.Close}, nil
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
