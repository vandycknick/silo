package forwarder

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/inetaf/tcpproxy"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/router"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const linkLocalSubnet = "169.254.0.0/16"

type TCPMetadata struct {
	VMID      string
	NetworkID string
}

func TCP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, route *router.Router, httpProxy *HTTPProxy, httpsProxy *HTTPSProxy, metadata TCPMetadata) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		localAddress := id.LocalAddress

		if !ec2MetadataAccess && linkLocal().Contains(localAddress) {
			r.Complete(true)
			return
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		flow := hooks.Flow{
			Protocol:   "tcp",
			SourceIP:   addressIP(id.RemoteAddress),
			SourcePort: id.RemotePort,
			DestIP:     addressIP(localAddress),
			DestPort:   id.LocalPort,
			VMID:       metadata.VMID,
			NetworkID:  metadata.NetworkID,
		}
		decision, err := route.Decide(context.Background(), flow)
		if err != nil {
			slog.Warn("tcp policy hook failed", "error", err)
			r.Complete(true)
			return
		}
		if decision.Action == hooks.RouteDeny {
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
			logCreateEndpointError("tcp", flow, tcpErr)
			return
		}
		inbound := gonet.NewTCPConn(&wq, ep)
		target := net.JoinHostPort(localAddress.String(), fmt.Sprint(id.LocalPort))
		if httpProxy != nil && httpProxy.ShouldHandle(flow, decision) {
			if err := httpProxy.Handle(context.Background(), inbound, flow, target); err != nil {
				slog.Debug("http proxy failed", "error", err, "target", target)
			}
			return
		}
		if httpsProxy != nil && httpsProxy.ShouldHandle(flow, decision) {
			if err := httpsProxy.Handle(context.Background(), inbound, flow, target, decision); err != nil {
				slog.Debug("https proxy failed", "error", err, "target", target)
			}
			return
		}

		outbound, err := net.Dial("tcp", target)
		if err != nil {
			slog.Debug("tcp outbound dial failed", "error", err, "target", target)
			_ = inbound.Close()
			return
		}
		proxyTCP(inbound, outbound)
	})
}

func proxyTCP(inbound net.Conn, outbound net.Conn) {
	remote := tcpproxy.DialProxy{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return outbound, nil
		},
	}
	remote.HandleConn(inbound)
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet)
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}

func addressIP(address tcpip.Address) net.IP {
	return net.IP(address.AsSlice())
}
