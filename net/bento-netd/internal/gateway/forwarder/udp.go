package forwarder

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	upstreamForwarder "github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const udpConnTrackTimeout = 90 * time.Second

func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, route *router.Router, metadata TCPMetadata) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		localAddress := id.LocalAddress

		if !ec2MetadataAccess && linkLocal().Contains(localAddress) || localAddress == header.IPv4Broadcast {
			return true
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		flow := hooks.Flow{
			Protocol:    "udp",
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
			log.WithError(err).Warn("udp policy hook failed")
			return false
		}
		if decision.Action == hooks.RouteDeny {
			return false
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return false
		}

		p, _ := upstreamForwarder.NewUDPProxy(&autoStoppingUDPListener{underlying: gonet.NewUDPConn(&wq, ep)}, func() (net.Conn, error) {
			return net.Dial("udp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(id.LocalPort))))
		})
		go func() {
			p.Run()
			ep.Close()
		}()
		return true
	})
}

type autoStoppingUDPListener struct {
	underlying udpConn
}

type udpConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

func (l *autoStoppingUDPListener) ReadFrom(b []byte) (int, net.Addr, error) {
	_ = l.underlying.SetReadDeadline(time.Now().Add(udpConnTrackTimeout))
	return l.underlying.ReadFrom(b)
}

func (l *autoStoppingUDPListener) WriteTo(b []byte, addr net.Addr) (int, error) {
	_ = l.underlying.SetReadDeadline(time.Now().Add(udpConnTrackTimeout))
	return l.underlying.WriteTo(b, addr)
}

func (l *autoStoppingUDPListener) SetReadDeadline(t time.Time) error {
	return l.underlying.SetReadDeadline(t)
}

func (l *autoStoppingUDPListener) Close() error {
	return l.underlying.Close()
}
