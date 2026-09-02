package virtualnetwork

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	upstreamForwarder "github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/gateway/publication"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/logfile"
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
	RunID     string
	NetworkID string
}

type PublicationOptions struct {
	Enabled bool
	Bind    publication.BindPolicy
	GuestIP netip.Addr
	Audit   *audit.Logger
}

type VirtualNetwork struct {
	configuration *types.Configuration
	stack         *stack.Stack
	networkSwitch *tap.Switch
	services      []networkService
	publications  *publication.Table
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

// New takes ownership of captureFile when it succeeds. Callers retain it when
// construction fails.
func New(ctx context.Context, networkConfig *config.NetworkConfig, captureFile *os.File, route *router.Router, dispatcher *packet.TCPDispatcher, flows *packet.FlowTracker, metadata Metadata, publicationOptions PublicationOptions) (*VirtualNetwork, error) {
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
	if captureFile != nil {
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, captureFile, math.MaxUint32)
		if err != nil {
			return nil, fmt.Errorf("cannot create sniffer: %w", err)
		}
	}

	stack, err := createStack(configuration, endpoint)
	if err != nil {
		return nil, fmt.Errorf("cannot create network stack: %w", err)
	}

	services, publications, err := addServices(ctx, configuration, stack, ipPool, route, dispatcher, flows, metadata, publicationOptions)
	if err != nil {
		stack.Close()
		return nil, fmt.Errorf("cannot add network services: %w", err)
	}

	return &VirtualNetwork{configuration: configuration, stack: stack, networkSwitch: networkSwitch, services: services, publications: publications, ipPool: ipPool, captureFile: captureFile}, nil
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
			n.closeErr = errors.Join(n.closeErr, logfile.SyncClose(n.captureFile))
		}
	})
	return n.closeErr
}

func addServices(ctx context.Context, configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool, route *router.Router, dispatcher *packet.TCPDispatcher, flows *packet.FlowTracker, metadata Metadata, publicationOptions PublicationOptions) ([]networkService, *publication.Table, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := packet.TCP(ctx, s, translation, &natLock, configuration.Ec2MetadataAccess, route, dispatcher, flows, packet.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := packet.UDP(ctx, s, translation, &natLock, configuration.Ec2MetadataAccess, route, flows, packet.TCPMetadata(metadata))
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	icmpForwarder := upstreamForwarder.ICMP(s, translation, &natLock)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)

	dnsServices, err := dnsServer(configuration, s)
	if err != nil {
		return nil, nil, err
	}
	dhcpService, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, nil, errors.Join(err, closeNetworkServices(dnsServices))
	}
	services := append(dnsServices, dhcpService)
	portsForwarder, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, nil, errors.Join(err, closeNetworkServices(services))
	}
	if !publicationOptions.Enabled {
		return services, nil, nil
	}
	publicationTable := publication.NewTable(portsForwarder)
	publicationService, err := publicationServer(configuration, s, publicationTable, publicationOptions)
	if err != nil {
		return nil, nil, errors.Join(err, publicationTable.Close(), closeNetworkServices(services))
	}
	services = append(services, publicationService)
	return services, publicationTable, nil
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

func dnsServer(configuration *types.Configuration, s *stack.Stack) ([]networkService, error) {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	tcpLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()), Port: uint16(53)}, ipv4.ProtocolNumber)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	server, err := dns.New(udpConn, tcpLn, configuration.DNS)
	if err != nil {
		_ = udpConn.Close()
		_ = tcpLn.Close()
		return nil, err
	}
	services := []networkService{
		{name: "dns udp server", serve: server.Serve, close: udpConn.Close},
		{name: "dns tcp server", serve: server.ServeTCP, close: tcpLn.Close},
	}
	return services, nil
}

func dhcpServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (networkService, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return networkService{}, err
	}
	return networkService{name: "dhcp server", serve: server.Serve, close: server.Underlying.Close}, nil
}

func forwardHostVM(configuration *types.Configuration, s *stack.Stack) (*upstreamForwarder.PortsForwarder, error) {
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
	return fw, nil
}

func publicationServer(configuration *types.Configuration, s *stack.Stack, table *publication.Table, options PublicationOptions) (networkService, error) {
	gatewayIP := net.ParseIP(configuration.GatewayIP).To4()
	if gatewayIP == nil {
		return networkService{}, fmt.Errorf("invalid publication gateway IPv4 address %q", configuration.GatewayIP)
	}
	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(gatewayIP), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		return networkService{}, err
	}
	server := &http.Server{
		Handler:           publication.Handler(table, publication.Policy{Bind: options.Bind, GuestIP: options.GuestIP}, options.Audit),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return networkService{
		name: "publication endpoint",
		serve: func() error {
			err := server.Serve(listener)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
		close: func() error {
			serverErr := server.Close()
			entries := table.All()
			tableErr := table.Close()
			for _, entry := range entries {
				options.Audit.RecordPublication("released", entry.Scope.AuditName(), entry.Local, entry.Remote, "allow", "")
			}
			return errors.Join(serverErr, tableErr)
		},
	}, nil
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
