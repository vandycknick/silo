package netnode

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

const (
	forwardCertificateTimeout         = time.Minute
	forwardCertificateRefreshTimeout  = 2 * time.Minute
	forwardCertificateRefreshInterval = time.Hour
)

type forwardCertificateIdentity struct {
	name string
	node tailcfg.StableNodeID
}

func eligibleForwardCertificate(s *ipnstate.Status, expected *ExpectedIdentity, hostname string) (forwardCertificateIdentity, error) {
	sni := ""
	if s != nil && s.Self != nil {
		sni = s.Self.DNSName
	}
	name, err := certificateName(s, expected, hostname, sni)
	if err != nil {
		return forwardCertificateIdentity{}, err
	}
	return forwardCertificateIdentity{name: name, node: s.Self.ID}, nil
}

// Caller holds n.mu. Status changes only publish/cancel an identity epoch;
// certificate I/O belongs to the worker, never the observation lock.
func (n *Node) observeCertificateIdentityLocked(s *ipnstate.Status) {
	if n.certWake == nil || n.ctx == nil {
		return
	}
	identity, _ := eligibleForwardCertificate(s, n.options.Identity, n.options.Declaration.Hostname)
	if n.closed || n.ctx.Err() != nil {
		identity = forwardCertificateIdentity{}
	}
	if identity == n.certIdentity {
		return
	}
	if n.certCancel != nil {
		n.certCancel()
	}
	n.certIdentity = identity
	n.certContext, n.certCancel = nil, nil
	if identity.name != "" {
		n.certContext, n.certCancel = context.WithCancel(n.ctx)
	}
	select {
	case n.certWake <- struct{}{}:
	default:
	}
}

func (n *Node) certificateState() (context.Context, forwardCertificateIdentity, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.certContext == nil {
		return nil, forwardCertificateIdentity{}, errors.New("certificate identity unavailable")
	}
	if err := n.certContext.Err(); err != nil {
		return nil, forwardCertificateIdentity{}, err
	}
	return n.certContext, n.certIdentity, nil
}

func (n *Node) startCertificateMaintenance(parent context.Context) func() {
	if n.certWake == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(forwardCertificateRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-n.certWake:
			case <-ticker.C:
			}
			identityCtx, identity, err := n.certificateState()
			if err != nil {
				continue
			}
			requestCtx, requestCancel := context.WithTimeout(identityCtx, forwardCertificateRefreshTimeout)
			stop := context.AfterFunc(ctx, requestCancel)
			_, _ = n.acquireForwardCertificate(requestCtx, identity, "background")
			stop()
			requestCancel()
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func certificateName(s *ipnstate.Status, expected *ExpectedIdentity, hostname, sni string) (string, error) {
	if s == nil || s.BackendState != "Running" || s.Self == nil || expired(s) || s.CurrentTailnet == nil || !s.CurrentTailnet.MagicDNSEnabled {
		return "", errors.New("certificate identity unavailable")
	}
	if err := expected.verify(s, hostname); err != nil {
		return "", err
	}
	name := canonical(s.Self.DNSName)
	request := canonical(sni)
	if request == "" || !strings.Contains(request, ".") || strings.ContainsAny(request, "*:/") || net.ParseIP(request) != nil || request != name {
		return "", errors.New("tls_name_mismatch")
	}
	for _, domain := range s.CertDomains {
		if canonical(domain) == name {
			return name, nil
		}
	}
	return "", errors.New("certificate identity ineligible")
}
func helloLease(hello *tls.ClientHelloInfo) *admittedConn {
	if c, ok := hello.Conn.(*tls.Conn); ok {
		if lease, ok := c.NetConn().(*admittedConn); ok {
			return lease
		}
	}
	if c, ok := hello.Conn.(*admittedConn); ok {
		return c
	}
	return nil
}
func (n *Node) forwardCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	lease := helloLease(hello)
	fail := func(reason string, err error) (*tls.Certificate, error) {
		if lease != nil {
			lease.outcome(reason, false)
		}
		return nil, err
	}
	request := canonical(hello.ServerName)
	if request == "" || !strings.Contains(request, ".") || strings.ContainsAny(request, "*:/") || net.ParseIP(request) != nil {
		return fail("tls_name_mismatch", errors.New("invalid TLS server name"))
	}
	identityCtx, identity, err := n.certificateState()
	if err != nil {
		return fail("tls_certificate_failed", err)
	}
	if request != identity.name {
		return fail("tls_name_mismatch", errors.New("tls_name_mismatch"))
	}
	// Provisioning survives a disconnected browser, but not an identity change
	// or node shutdown. Waiting for the shared acquisition slot uses this budget.
	ctx, cancel := context.WithTimeout(identityCtx, forwardCertificateTimeout)
	defer cancel()
	cert, err := n.acquireForwardCertificate(ctx, identity, "handshake")
	if err != nil {
		return fail("tls_certificate_failed", err)
	}
	return cert, nil
}

func (n *Node) acquireForwardCertificate(ctx context.Context, identity forwardCertificateIdentity, source string) (_ *tls.Certificate, err error) {
	started := time.Now()
	slog.Debug("tailscale certificate acquisition started", "dns_name", identity.name, "source", source)
	defer func() {
		level := slog.LevelDebug
		if err != nil && !errors.Is(err, context.Canceled) {
			level = slog.LevelWarn
		}
		slog.Log(context.Background(), level, "tailscale certificate acquisition finished",
			"dns_name", identity.name, "source", source, "duration", time.Since(started), "error", err)
	}()
	select {
	case n.certSlot <- struct{}{}:
		defer func() { <-n.certSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, err := n.LocalClient()
	if err != nil {
		return nil, err
	}
	verify := func() error {
		statusCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		status, err := client.StatusWithoutPeers(statusCtx)
		if err != nil {
			return err
		}
		current, err := eligibleForwardCertificate(status, n.options.Identity, n.options.Declaration.Hostname)
		if err != nil {
			return err
		}
		if current != identity {
			return errors.New("certificate identity changed")
		}
		return nil
	}
	if err := verify(); err != nil {
		return nil, err
	}
	// Positive validity keeps renewal synchronous under our owned context.
	// Zero validity can start an upstream renewal with a background context.
	certPEM, keyPEM, err := client.CertPairWithValidity(ctx, identity.name, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &cert, nil
}
