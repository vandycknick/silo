package netnode

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

// admittedConn owns one shared flow slot until the socket and all of its HTTP
// handlers have finished. Outcomes cannot change after terminal publication.
type admittedConn struct {
	net.Conn
	node                       *Node
	ctx                        context.Context
	cancel                     context.CancelFunc
	mu                         sync.Mutex
	event                      InboundEvent
	start                      time.Time
	closed, terminal, hijacked bool
	httpOwned, httpTracked     bool
	refs                       int
	stop                       func() bool
}

func (c *admittedConn) outcome(reason string, connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal {
		return
	}
	if connected {
		c.event.Decision, c.event.Reason = "allow", "connected"
	} else if c.event.Decision != "allow" {
		c.event.Reason = reason
	}
}
func (c *admittedConn) acquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.refs++
	return true
}
func (c *admittedConn) release() { c.mu.Lock(); c.refs--; c.finishLocked(); c.mu.Unlock() }
func (c *admittedConn) finishLocked() {
	if !c.closed || c.refs != 0 || c.terminal {
		return
	}
	c.terminal = true
	if c.stop != nil {
		c.stop()
	}
	c.event.Duration = time.Since(c.start)
	if c.node.options.Audit != nil {
		c.node.options.Audit(c.event)
	}
	c.node.mu.Lock()
	delete(c.node.active, c)
	c.node.mu.Unlock()
	c.node.options.Flows.Done()
	<-c.node.slots
	c.node.relays.Done()
}
func (c *admittedConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	err := c.Conn.Close()
	c.mu.Lock()
	c.finishLocked()
	c.mu.Unlock()
	return err
}
func (c *admittedConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Close()
}
func (n *Node) admit(in net.Conn, event InboundEvent, reason string) *admittedConn {
	start := time.Now()
	n.mu.Lock()
	if n.closed || !n.started || n.ctx.Err() != nil {
		reason = "session_closed"
	} else if reason != "forward_unavailable" && n.options.Identity != nil && !n.running {
		reason = "node_identity_unverified"
	}
	if reason == "" {
		select {
		case n.slots <- struct{}{}:
		default:
			reason = "connection_limit"
		}
		if reason == "" && (n.options.Flows == nil || !n.options.Flows.Start()) {
			<-n.slots
			reason = "session_draining"
		}
	}
	if reason != "" {
		n.mu.Unlock()
		in.Close()
		event.Reason = reason
		event.Duration = time.Since(start)
		if n.options.Audit != nil {
			n.options.Audit(event)
		}
		return nil
	}
	n.relays.Add(1)
	c := &admittedConn{Conn: in, node: n, event: event, start: start}
	c.ctx, c.cancel = context.WithCancel(n.ctx)
	if n.active == nil {
		n.active = make(map[*admittedConn]struct{})
	}
	n.active[c] = struct{}{}
	c.mu.Lock()
	c.stop = context.AfterFunc(n.ctx, func() { c.Close() })
	c.mu.Unlock()
	n.mu.Unlock()
	return c
}
func (n *Node) relayGuest(c *admittedConn, port uint16) {
	if !c.acquire() {
		return
	}
	defer c.release()
	if n.options.Guest == nil {
		c.outcome("guest_unattached", false)
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	out, err := n.options.Guest.DialGuest(ctx, port)
	cancel()
	if err != nil {
		c.outcome("guest_connection_failed", false)
		return
	}
	defer out.Close()
	c.outcome("connected", true)
	Relay(c.ctx, c, out)
}

type admissionListener struct {
	net.Listener
	node    *Node
	forward policy.Forward
	ctx     context.Context
}

func (l *admissionListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		reason := "guest_not_contacted"
		if l.forward.Protocol == policy.ForwardProtocolHTTPS {
			reason = "tls_handshake_failed"
		}
		event := InboundEvent{Peer: peer, Port: l.forward.ListenPort, Forward: l.forward.Name, TargetPort: l.forward.GuestPort, Protocol: string(l.forward.Protocol), Decision: "deny", Reason: reason}
		forced := ""
		if l.ctx != nil && l.ctx.Err() != nil {
			forced = "session_closed"
		}
		if c := l.node.admit(raw, event, forced); c != nil {
			if l.ctx != nil && l.ctx.Err() != nil {
				c.Close()
				return nil, net.ErrClosed
			}
			return c, nil
		}
		if forced != "" {
			return nil, net.ErrClosed
		}
	}
}
func (n *Node) startForwards(ctx context.Context) (func(), error) {
	listeners := make([]*admissionListener, 0, len(n.options.Forwards))
	for _, f := range n.options.Forwards {
		raw, err := n.Listen("tcp", ":"+strconv.Itoa(int(f.ListenPort)))
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("forward %q port %d: %w", f.Name, f.ListenPort, err)
		}
		listeners = append(listeners, &admissionListener{Listener: raw, node: n, forward: f})
	}
	var cleanups []func()
	for _, l := range listeners {
		if l.forward.Protocol == policy.ForwardProtocolHTTPS {
			cleanups = append(cleanups, n.serveHTTPS(ctx, l))
			continue
		}
		cleanups = append(cleanups, n.serveTCP(ctx, l))
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			for _, l := range listeners {
				l.Close()
				n.closeForwardConnections(l.forward.Name)
			}
			for _, closeService := range cleanups {
				closeService()
			}
			if ctx.Err() != nil {
				n.relays.Wait()
			}
		})
	}
	stop := context.AfterFunc(ctx, cleanup)
	return func() { stop(); cleanup() }, nil
}

func (n *Node) closeForwardConnections(name string) {
	n.mu.Lock()
	var sockets []*admittedConn
	for c := range n.active {
		if c.event.Forward == name {
			sockets = append(sockets, c)
		}
	}
	n.mu.Unlock()
	for _, c := range sockets {
		c.Close()
	}
}

func (n *Node) serveTCP(ctx context.Context, listener *admissionListener) func() {
	ctx, cancel := context.WithCancel(ctx)
	listener.ctx = ctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		var connections sync.WaitGroup
		defer connections.Wait()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					slog.Warn("forward listener stopped", "forward", listener.forward.Name, "port", listener.forward.ListenPort, "error", err)
				}
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				c := conn.(*admittedConn)
				defer c.Close()
				n.relayGuest(c, listener.forward.GuestPort)
			}()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { cancel(); listener.Close(); n.closeForwardConnections(listener.forward.Name); <-done })
	}
}
