package publication

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/inetaf/tcpproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type TCPForwarder struct {
	stack   *stack.Stack
	mu      sync.Mutex
	proxies map[string]*tcpproxy.Proxy
}

func NewTCPForwarder(networkStack *stack.Stack) *TCPForwarder {
	return &TCPForwarder{stack: networkStack, proxies: make(map[string]*tcpproxy.Proxy)}
}

func (f *TCPForwarder) Expose(protocol types.TransportProtocol, local, remote string) error {
	if protocol != types.TCP {
		return fmt.Errorf("publication protocol %q is not supported", protocol)
	}
	if f == nil || f.stack == nil {
		return errors.New("publication network stack is not configured")
	}
	listenNetwork, err := tcpNetwork(local)
	if err != nil {
		return err
	}
	remoteAddress, err := guestAddress(remote)
	if err != nil {
		return err
	}

	key := publicationKey(protocol, local)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.proxies[key]; exists {
		return fmt.Errorf("publication proxy already running for %s", local)
	}

	proxy := &tcpproxy.Proxy{
		ListenFunc: func(_ string, address string) (net.Listener, error) {
			return net.Listen(listenNetwork, address)
		},
	}
	proxy.AddRoute(local, &tcpproxy.DialProxy{
		Addr: remote,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return gonet.DialContextTCP(ctx, f.stack, remoteAddress, ipv4.ProtocolNumber)
		},
	})
	if err := proxy.Start(); err != nil {
		return err
	}
	f.proxies[key] = proxy
	go func() {
		if err := proxy.Wait(); err != nil {
			slog.Debug("publication proxy stopped", "error", err, "local", local, "remote", remote)
		}
	}()
	return nil
}

func (f *TCPForwarder) Unexpose(protocol types.TransportProtocol, local string) error {
	if f == nil {
		return errors.New("publication forwarder is not configured")
	}
	key := publicationKey(protocol, local)
	f.mu.Lock()
	defer f.mu.Unlock()
	proxy, exists := f.proxies[key]
	if !exists {
		return fmt.Errorf("publication proxy not found for %s", local)
	}
	delete(f.proxies, key)
	return proxy.Close()
}

func tcpNetwork(address string) (string, error) {
	host, _, err := splitAddress(address, "local")
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("local host %q must be an IP address", host)
	}
	if ip.Unmap().Is4() {
		return "tcp4", nil
	}
	return "tcp6", nil
}

func guestAddress(address string) (tcpip.FullAddress, error) {
	host, port, err := splitAddress(address, "remote")
	if err != nil {
		return tcpip.FullAddress{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().Is4() {
		return tcpip.FullAddress{}, fmt.Errorf("remote host %q must be an IPv4 address", host)
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(ip.Unmap().As4()),
		Port: port,
	}, nil
}
