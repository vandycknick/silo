package forwarder

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/inetaf/tcpproxy"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
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
		flow := hooks.Flow{
			Protocol:   "tcp",
			SourceIP:   addressIP(id.RemoteAddress),
			SourcePort: id.RemotePort,
			DestIP:     addressIP(localAddress),
			DestPort:   id.LocalPort,
			VMID:       metadata.VMID,
			NetworkID:  metadata.NetworkID,
		}
		flow = route.WithFlowID(flow)

		if !ec2MetadataAccess && linkLocal().Contains(localAddress) {
			route.RecordFlowOutcome(flow, deniedFlow("metadata_disabled"), "metadata_disabled")
			r.Complete(true)
			return
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()
		flow.DestIP = addressIP(localAddress)
		decision, err := route.Decide(context.Background(), flow)
		if err != nil {
			slog.Warn("tcp policy hook failed", "error", err)
			route.RecordFlowOutcome(flow, deniedFlow("policy_error"), "policy_error")
			r.Complete(true)
			return
		}
		if decision.Action == hooks.RouteDeny {
			route.RecordFlow(flow, decision)
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
			logCreateEndpointError("tcp", flow, tcpErr)
			route.RecordFlowOutcome(flow, decision, "endpoint_error")
			return
		}
		inbound := gonet.NewTCPConn(&wq, ep)
		target := net.JoinHostPort(localAddress.String(), fmt.Sprint(id.LocalPort))
		if httpProxy != nil && httpProxy.ShouldHandle(flow, decision) {
			route.RecordFlowOutcome(flow, decision, "classify")
			if err := httpProxy.Handle(context.Background(), inbound, flow, target); err != nil {
				slog.Debug("http proxy failed", "error", err, "target", target)
			}
			return
		}
		if httpsProxy != nil && httpsProxy.ShouldHandle(flow, decision) {
			route.RecordFlowOutcome(flow, decision, "classify")
			if err := httpsProxy.Handle(context.Background(), inbound, flow, target, decision); err != nil {
				slog.Debug("https proxy failed", "error", err, "target", target)
			}
			return
		}

		outbound, err := net.Dial("tcp", target)
		if err != nil {
			slog.Debug("tcp outbound dial failed", "error", err, "target", target)
			_ = inbound.Close()
			route.RecordFlowOutcome(flow, decision, "upstream_error")
			return
		}
		proxyTCP(inbound, outbound)
		route.RecordFlow(flow, decision)
	})
}

func deniedFlow(reason string) hooks.RouteDecision {
	return hooks.RouteDecision{Action: hooks.RouteDeny, Reason: reason}
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
