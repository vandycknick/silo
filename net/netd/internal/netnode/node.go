// Package netnode owns one embedded node, strict egress, DNS provenance and
// bounded connection-attempt admission. It never queries guest status.
package netnode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/vandycknick/silo/net/netd/internal/bootenv"
	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type Guest interface {
	DialGuest(context.Context, uint16) (net.Conn, error)
}
type Flows interface {
	Start() bool
	Done()
}
type InboundEvent struct {
	Peer             netip.AddrPort
	Port             uint16
	Decision, Reason string
	Duration         time.Duration
}
type Options struct {
	Dir         string
	Declaration policy.TailscaleDecl
	Secrets     credentials.Source
	Guest       Guest
	Flows       Flows
	Audit       func(InboundEvent)
}

type Node struct {
	server              *tsnet.Server
	options             Options
	mu                  sync.Mutex
	started, closed     bool
	initialized         bool
	cancel              context.CancelFunc
	ctx                 context.Context
	done                chan struct{}
	client              *local.Client
	dial                func(context.Context, netip.AddrPort) (net.Conn, error)
	running             bool
	suffix, fingerprint string
	short               map[string]string
	fullNames           map[string]struct{}
	knownShort          map[string]struct{}
	knownSuffixes       map[string]struct{}
	classificationFull  bool
	provenance          map[netip.Addr]time.Time
	quarantined         map[netip.Addr]time.Time
	relays              sync.WaitGroup
	slots               chan struct{}
	closeOnce           sync.Once
	closeErr            error
}

func New(o Options) (*Node, error) {
	if o.Declaration.Hostname == "" {
		o.Declaration.Hostname = o.Declaration.Name
	}
	key := ""
	if o.Secrets != nil {
		if value, ok := o.Secrets.Lookup(o.Declaration.Name + ".tailscale.auth_key"); ok {
			key = string(value)
		}
	}
	if !literalEnrollmentKey(key) {
		return nil, errors.New("tailscale auth_key must be a literal tskey-auth- enrollment key; OAuth/client-secret/WIF discovery is not supported by netd")
	}
	return &Node{options: o, done: make(chan struct{}), slots: make(chan struct{}, 256), short: make(map[string]string), fullNames: make(map[string]struct{}), knownShort: make(map[string]struct{}), knownSuffixes: make(map[string]struct{}), provenance: make(map[netip.Addr]time.Time), quarantined: make(map[netip.Addr]time.Time), server: &tsnet.Server{
		Dir: o.Dir, Hostname: o.Declaration.Hostname, AdvertiseTags: append([]string(nil), o.Declaration.Tags...), Ephemeral: o.Declaration.Ephemeral,
		ControlURL: o.Declaration.ControlURL, AuthKey: key,
		UserLogf: func(format string, args ...any) { slog.Info("tailscale", "message", fmt.Sprintf(format, args...)) },
	}}, nil
}

// Pinned tsnet.Start resolves tskey-client-* via OAuth under its own shutdown
// context. Only literal enrollment keys can enter Start; no queries, URLs,
// whitespace or credential-discovery attributes are accepted.
func literalEnrollmentKey(key string) bool {
	if key == "" {
		return true
	}
	const prefix = "tskey-auth-"
	if !strings.HasPrefix(key, prefix) || len(key) == len(prefix) || len(key) > 4096 {
		return false
	}
	for _, c := range key[len(prefix):] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Start transfers initialization to one owner. Close cancels Up and joins that
// owner before calling Server.Close, including when Start is still initializing.
func (n *Node) Start(parent context.Context) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started || n.closed {
		return
	}
	n.started = true
	ctx, cancel := context.WithCancel(parent)
	n.cancel = cancel
	n.ctx = ctx
	go n.run(ctx)
}

func (n *Node) run(ctx context.Context) {
	defer close(n.done)
	if ctx.Err() != nil {
		return
	}
	if err := n.server.Start(); err != nil {
		slog.Warn("tailscale start failed", "error", err)
		return
	}
	n.mu.Lock()
	n.initialized = true
	n.mu.Unlock()
	client, err := n.server.LocalClient()
	if err != nil {
		slog.Warn("tailscale local client failed", "error", err)
		return
	}
	n.server.RegisterFallbackTCPHandler(n.Fallback)
	n.mu.Lock()
	n.client = client
	n.mu.Unlock()
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); n.watch(ctx, client) }()
	defer func() { <-watchDone }()
	slog.Info("tailscale guest IPv6 transport unavailable", "guest_stack", "IPv4 only")
	for {
		upCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		status, upErr := n.server.Up(upCtx)
		cancel()
		if upErr == nil {
			dial, err := strictDialer(n.server)
			if err == nil {
				n.mu.Lock()
				n.dial = dial
				n.mu.Unlock()
			} else {
				slog.Warn("tailscale strict adapter unavailable", "error", err)
			}
		}
		statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		observed, statusErr := client.Status(statusCtx)
		cancel()
		if statusErr == nil {
			status = observed
		} else {
			status = nil
		}
		n.observe(status)
		if status != nil {
			slog.Info("tailscale state", "state", status.BackendState, "auth_url", status.AuthURL)
		}
		if upErr != nil && ctx.Err() == nil {
			slog.Debug("tailscale disconnected", "error", upErr)
		}
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			n.observe(nil)
			return
		case <-timer.C:
		}
	}
}

func (n *Node) observe(s *ipnstate.Status) {
	short := make(map[string]string)
	full := make(map[string]struct{})
	suffix := ""
	running := s != nil && s.BackendState == "Running"
	parts := []string{fmt.Sprint(running)}
	if s != nil {
		if s.CurrentTailnet != nil {
			suffix = strings.ToLower(strings.TrimSuffix(s.CurrentTailnet.MagicDNSSuffix, "."))
		}
		parts = append(parts, suffix)
		if s.Self != nil {
			parts = append(parts, fmt.Sprint(s.Self.ID, s.Self.TailscaleIPs))
		}
		for _, p := range s.Peer {
			if p == nil {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
			if name == "" {
				continue
			}
			label, _, _ := strings.Cut(name, ".")
			if len(full) < 4096 {
				full[name] = struct{}{}
			}
			if _, ok := short[label]; ok {
				short[label] = ""
			} else if len(short) < 4096 {
				short[label] = name
			}
			parts = append(parts, fmt.Sprint(name, p.TailscaleIPs, p.Online))
		}
	}
	sort.Strings(parts)
	fingerprint := strings.Join(parts, "|")
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fingerprint != fingerprint {
		// Invalidate positive provenance, but keep still-cacheable addresses
		// classified until their original TTL expires. A guest's cached answer
		// must not become a direct-host route on disconnect or peer removal.
		n.pruneAddresses(time.Now())
		for ip, until := range n.provenance {
			if until.After(n.quarantined[ip]) {
				n.quarantined[ip] = until
			}
		}
		clear(n.provenance)
		n.fingerprint = fingerprint
	}
	n.short = short
	n.fullNames = full
	// A disappeared peer or disconnected status must not turn a known short
	// name into a host DNS query. Retain bounded negative classification, while
	// address provenance is invalidated above. Exhaustion fails DNS closed.
	for name := range short {
		if _, known := n.knownShort[name]; !known {
			if len(n.knownShort) < 4096 {
				n.knownShort[name] = struct{}{}
			} else {
				n.classificationFull = true
			}
		}
	}
	if len(short) == 4096 || len(full) == 4096 {
		n.classificationFull = true
	}
	if suffix != "" {
		if _, known := n.knownSuffixes[suffix]; !known {
			if len(n.knownSuffixes) < 32 {
				n.knownSuffixes[suffix] = struct{}{}
			} else {
				n.classificationFull = true
			}
		}
	}
	n.suffix = suffix
	n.running = running
}

func (n *Node) watch(ctx context.Context, client *local.Client) {
	for ctx.Err() == nil {
		watcher, err := client.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialNetMap)
		if err == nil {
			for {
				_, err = watcher.Next()
				if err != nil {
					break
				}
				bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
				status, statusErr := client.Status(bounded)
				cancel()
				if statusErr != nil {
					n.observe(nil)
				} else {
					n.observe(status)
				}
			}
			_ = watcher.Close()
		}
		n.observe(nil)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func InRange(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip.Unmap()) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}
func (n *Node) IsDestination(ip netip.Addr) bool {
	if InRange(ip) {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pruneAddresses(time.Now())
	_, positive := n.provenance[ip.Unmap()]
	_, quarantined := n.quarantined[ip.Unmap()]
	return positive || quarantined
}

// Caller holds mu. Both maps share one 4096-address classification budget.
func (n *Node) pruneAddresses(now time.Time) {
	for _, entries := range []map[netip.Addr]time.Time{n.provenance, n.quarantined} {
		for ip, until := range entries {
			if !now.Before(until) {
				delete(entries, ip)
			}
		}
	}
}
func (n *Node) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, string, error) {
	n.mu.Lock()
	dial, ready := n.dial, n.running && !n.closed
	n.mu.Unlock()
	if !ready || dial == nil {
		return nil, "tunnel_not_connected", errors.New("tailscale disconnected")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(bounded, dst)
	if err != nil {
		return nil, "tunnel_error", err
	}
	return conn, "", nil
}

func (n *Node) Fallback(src, dst netip.AddrPort) (func(net.Conn), bool) {
	return func(conn net.Conn) { n.relay(src, dst, conn) }, true
}
func (n *Node) relay(src, dst netip.AddrPort, in net.Conn) {
	start := time.Now()
	event := InboundEvent{Peer: src, Port: dst.Port(), Decision: "deny"}
	tracked := false
	defer func() {
		_ = in.Close()
		event.Duration = time.Since(start)
		if n.options.Audit != nil {
			n.options.Audit(event)
		}
		if tracked {
			n.relays.Done()
		}
	}()
	n.mu.Lock()
	if n.closed || !n.started {
		n.mu.Unlock()
		event.Reason = "session_closed"
		return
	}
	n.relays.Add(1)
	tracked = true
	ctx := n.ctx
	n.mu.Unlock()
	if dst.Port() == 22 {
		event.Reason = "ssh_reserved"
		return
	}
	select {
	case n.slots <- struct{}{}:
		defer func() { <-n.slots }()
	default:
		event.Reason = "connection_limit"
		return
	}
	if n.options.Flows == nil || !n.options.Flows.Start() {
		event.Reason = "session_draining"
		return
	}
	defer n.options.Flows.Done()
	if n.options.Guest == nil {
		event.Reason = "guest_unattached"
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	out, err := n.options.Guest.DialGuest(dialCtx, dst.Port())
	cancel()
	if err != nil {
		event.Reason = "guest_connection_failed"
		return
	}
	defer out.Close()
	event.Decision = "allow"
	event.Reason = "connected"
	Relay(ctx, in, out)
}

// Relay preserves TCP half closes and actively closes both sockets on shutdown.
func Relay(ctx context.Context, a, b net.Conn) {
	stop := context.AfterFunc(ctx, func() { _ = a.Close(); _ = b.Close() })
	defer stop()
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			_ = a.Close()
			_ = b.Close()
			return
		}
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}

func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closed = true
		started := n.started
		if n.cancel != nil {
			n.cancel()
		}
		n.mu.Unlock()
		if started {
			<-n.done
			n.mu.Lock()
			initialized := n.initialized
			n.mu.Unlock()
			if initialized {
				n.closeErr = n.server.Close()
			}
		}
		n.relays.Wait()
	})
	return n.closeErr
}
