package netnode

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

type forwardLeaseKey struct{}
type forwardTransport struct {
	node      *Node
	port      uint16
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	sockets   map[*forwardSocket]struct{}
	dials     sync.WaitGroup
	transport *http.Transport
}
type forwardSocket struct {
	net.Conn
	owner *forwardTransport
	once  sync.Once
}

func (c *forwardSocket) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.sockets, c); c.owner.mu.Unlock() })
	return err
}
func (f *forwardTransport) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, net.ErrClosed
	}
	f.dials.Add(1)
	f.mu.Unlock()
	defer f.dials.Done()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(f.ctx, cancel)
	defer stop()
	if f.node.options.Guest == nil {
		return nil, errors.New("guest unattached")
	}
	raw, err := f.node.options.Guest.DialGuest(ctx, f.port)
	if err != nil {
		return nil, err
	}
	c := &forwardSocket{Conn: raw, owner: f}
	f.mu.Lock()
	if f.closed || ctx.Err() != nil {
		f.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	f.sockets[c] = struct{}{}
	f.mu.Unlock()
	if lease, ok := ctx.Value(forwardLeaseKey{}).(*admittedConn); ok {
		lease.outcome("connected", true)
	}
	return c, nil
}
func (f *forwardTransport) close() {
	f.mu.Lock()
	f.closed = true
	f.cancel()
	sockets := make([]*forwardSocket, 0, len(f.sockets))
	for c := range f.sockets {
		sockets = append(sockets, c)
	}
	f.mu.Unlock()
	f.transport.CloseIdleConnections()
	for _, c := range sockets {
		c.Close()
	}
	f.dials.Wait()
	f.transport.CloseIdleConnections()
}
func forwardHost(host, dns string, port uint16) bool {
	if dns == "" {
		return false
	}
	if !strings.Contains(host, ":") {
		return port == 443 && canonical(host) == dns
	}
	name, p, err := net.SplitHostPort(host)
	return err == nil && canonical(name) == dns && p == strconv.Itoa(int(port))
}
func (n *Node) forwardProxy(ctx context.Context, port uint16, listenPort uint16) (http.Handler, *forwardTransport) {
	lifetime, cancel := context.WithCancel(ctx)
	f := &forwardTransport{node: n, port: port, ctx: lifetime, cancel: cancel, sockets: make(map[*forwardSocket]struct{})}
	f.transport = &http.Transport{Proxy: nil, DialContext: f.dial, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 30 * time.Second}
	proxy := &httputil.ReverseProxy{
		Transport: f.transport, FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "guest.invalid:" + strconv.Itoa(int(port))
			r.Out.Host = r.In.Host
			for key := range r.Out.Header {
				lower := strings.ToLower(key)
				if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
					r.Out.Header.Del(key)
				}
			}
			r.SetXForwarded()
		},
		ModifyResponse: func(r *http.Response) error {
			if c, ok := r.Request.Context().Value(forwardLeaseKey{}).(*admittedConn); ok {
				c.outcome("connected", true)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			if c, ok := r.Context().Value(forwardLeaseKey{}).(*admittedConn); ok {
				c.outcome("guest_connection_failed", false)
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lease, _ := r.Context().Value(forwardLeaseKey{}).(*admittedConn)
		if lease == nil || !lease.acquire() {
			http.Error(w, "Service Unavailable", 503)
			return
		}
		defer func() {
			lease.mu.Lock()
			hijacked := lease.hijacked
			lease.mu.Unlock()
			if hijacked {
				lease.Close()
			}
			lease.release()
		}()
		n.mu.Lock()
		running := !n.closed && n.started && (n.options.Identity == nil || n.running)
		dns := ""
		if n.lastKnown != nil {
			dns = canonical(n.lastKnown.DNSName)
		}
		n.mu.Unlock()
		if !running {
			lease.outcome("node_identity_unverified", false)
			http.Error(w, "Service Unavailable", 503)
			return
		}
		if !forwardHost(r.Host, dns, listenPort) {
			lease.outcome("http_host_mismatch", false)
			http.Error(w, "Misdirected Request", 421)
			return
		}
		if r.Method == http.MethodConnect {
			lease.outcome("guest_not_contacted", false)
			http.Error(w, "Method Not Allowed", 405)
			return
		}
		lease.outcome("guest_not_contacted", false)
		proxy.ServeHTTP(w, r)
	})
	return handler, f
}
func tlsLease(c net.Conn) *admittedConn {
	if tlsConn, ok := c.(*tls.Conn); ok {
		lease, _ := tlsConn.NetConn().(*admittedConn)
		return lease
	}
	lease, _ := c.(*admittedConn)
	return lease
}
func (n *Node) serveHTTPS(ctx context.Context, listener *admissionListener) func() {
	return n.serveForwardTLS(ctx, listener, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: n.forwardCertificate})
}

func (n *Node) serveForwardTLS(ctx context.Context, listener *admissionListener, config *tls.Config) func() {
	ctx, cancel := context.WithCancel(ctx)
	listener.ctx = ctx
	var inner http.Handler
	handler, transport := n.forwardProxy(ctx, listener.forward.GuestPort, listener.forward.ListenPort)
	inner = handler
	var serving sync.WaitGroup
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serving.Add(1)
		defer serving.Done()
		// The connection's serving reference prevents Add racing cleanup's Wait.
		inner.ServeHTTP(w, r)
	})
	// Allow the bounded status lookup and serialized certificate acquisition to
	// finish before net/http's shared TLS-handshake/header deadline expires.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 75 * time.Second, IdleTimeout: 60 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			lease := tlsLease(c)
			serving.Add(1)
			lease.mu.Lock()
			lease.httpTracked = true
			if !lease.terminal {
				lease.refs++
				lease.httpOwned = true
			}
			lease.mu.Unlock()
			return context.WithValue(ctx, forwardLeaseKey{}, lease)
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			lease := tlsLease(c)
			if lease == nil || (state != http.StateClosed && state != http.StateHijacked) {
				return
			}
			handshakeComplete := false
			if tlsConn, ok := c.(*tls.Conn); ok {
				handshakeComplete = tlsConn.ConnectionState().HandshakeComplete
			}
			lease.mu.Lock()
			if !lease.terminal && handshakeComplete && lease.event.Reason == "tls_handshake_failed" {
				lease.event.Reason = "guest_not_contacted"
			}
			if state == http.StateHijacked {
				lease.hijacked = true
			}
			if lease.httpOwned {
				lease.httpOwned = false
				lease.refs--
				lease.finishLocked()
			}
			tracked := lease.httpTracked
			lease.httpTracked = false
			lease.mu.Unlock()
			if tracked {
				serving.Done()
			}
		},
	}
	tlsListener := tls.NewListener(listener, config)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			slog.Warn("HTTPS forward stopped", "forward", listener.forward.Name, "port", listener.forward.ListenPort)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			tlsListener.Close()
			server.Close()
			n.closeForwardConnections(listener.forward.Name)
			transport.close()
			<-done
			serving.Wait()
		})
	}
}
