package netnode

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"tailscale.com/tsnet"
)

// strictDialer is the ONLY unstable Tailscale API adapter. Pinned to v1.102.5.
// Server.Dial selects the host dialer when PeerForIP stops recognizing a peer,
// even for tailnet ranges. Calling the netstack hook directly cannot do that.
// Capture only after Up; never mutate the shared dialer or its callbacks.
func strictDialer(s *tsnet.Server) (func(context.Context, netip.AddrPort) (net.Conn, error), error) {
	if s == nil || s.Sys() == nil {
		return nil, errors.New("missing tsnet system")
	}
	d, ok := s.Sys().Dialer.GetOK()
	if !ok || d == nil || d.NetstackDialTCP == nil {
		return nil, errors.New("missing tsnet netstack TCP dialer")
	}
	return d.NetstackDialTCP, nil
}
