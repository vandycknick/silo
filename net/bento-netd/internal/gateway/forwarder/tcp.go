package forwarder

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/inetaf/tcpproxy"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const linkLocalSubnet = "169.254.0.0/16"

type TCPMetadata struct {
	VMID        string
	NetworkID   string
	ProfileName string
}

func TCP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, route *router.Router, metadata TCPMetadata) *tcp.Forwarder {
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
			Protocol:    "tcp",
			SourceIP:    addressIP(id.RemoteAddress),
			SourcePort:  id.RemotePort,
			DestIP:      addressIP(localAddress),
			DestPort:    id.LocalPort,
			VMID:        metadata.VMID,
			NetworkID:   metadata.NetworkID,
			ProfileName: metadata.ProfileName,
		}
		decision, err := route.Decide(context.Background(), flow)
		if err != nil {
			log.WithError(err).Warn("tcp policy hook failed")
			r.Complete(true)
			return
		}
		if decision.Action == hooks.RouteDeny {
			r.Complete(true)
			return
		}

		outbound, err := net.Dial("tcp", net.JoinHostPort(localAddress.String(), fmt.Sprint(id.LocalPort)))
		if err != nil {
			log.Tracef("net.Dial() = %v", err)
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			_ = outbound.Close()
			return
		}

		remote := tcpproxy.DialProxy{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return outbound, nil
			},
		}
		remote.HandleConn(gonet.NewTCPConn(&wq, ep))
	})
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet)
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}

func addressIP(address tcpip.Address) net.IP {
	return net.IP(address.AsSlice())
}
