package forwarder

import (
	"context"
	"net"

	"github.com/inetaf/tcpproxy"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

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
