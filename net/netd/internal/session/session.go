// Package session owns all state and resources belonging to one VM connection.
package session

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/forwarder"
	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/registry"
	"github.com/vandycknick/silo/net/netd/internal/virtualnetwork"
)

type Spec struct {
	VMID      string
	NetworkID string
	Stack     config.NetworkConfig
	Policy    *policy.Policy
	CACert    string
	CAKey     string
}

type Shared struct {
	Audit        *audit.Logger
	Intelligence *registry.IntelligencePool
}

type Session struct {
	ctx     context.Context
	cancel  context.CancelFunc
	flows   *packet.FlowTracker
	network *virtualnetwork.VirtualNetwork

	mu      sync.Mutex
	conn    net.Conn
	started bool
	closed  bool
	runDone chan struct{}

	closeOnce sync.Once
	closeErr  error
}

func New(spec Spec, shared Shared) (*Session, error) {
	if spec.Policy == nil {
		return nil, errors.New("session policy is required")
	}
	if spec.Policy.HasRegistries() && shared.Intelligence == nil {
		return nil, errors.New("registry policy requires shared package intelligence")
	}
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	flows := packet.NewFlowTracker()
	route := router.New(spec.Policy, shared.Audit)
	credentialManager, err := credentials.NewManagerFromEnvironment()
	if err != nil {
		cancel()
		return nil, err
	}
	dispatcher := packet.NewTCPDispatcher()
	httpsProxy, err := forwarder.NewHTTPSProxy(route, spec.CACert, spec.CAKey, credentialManager)
	if err != nil {
		cancel()
		return nil, err
	}
	var certificateAuthority *forwarder.CertificateAuthority
	if httpsProxy != nil {
		certificateAuthority = httpsProxy.CertificateAuthority()
	} else if route.HasRegistries() {
		certificateAuthority, err = forwarder.LoadCertificateAuthority(spec.CACert, spec.CAKey)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if httpProxy := forwarder.NewHTTPProxy(route); httpProxy != nil {
		if err := dispatcher.Register(packet.EndpointHTTP, httpProxy); err != nil {
			cancel()
			return nil, err
		}
	}
	registryProxy, err := forwarder.NewRegistryProxy(route, certificateAuthority, httpsProxy, shared.Intelligence)
	if err != nil {
		cancel()
		return nil, err
	}
	if registryProxy != nil {
		if err := dispatcher.Register(packet.EndpointRegistries, registryProxy); err != nil {
			cancel()
			return nil, err
		}
	}
	if httpsProxy != nil {
		if err := dispatcher.Register(packet.EndpointHTTPS, httpsProxy); err != nil {
			cancel()
			return nil, err
		}
	}
	network, err := virtualnetwork.New(
		lifetimeCtx,
		&spec.Stack,
		route,
		dispatcher,
		flows,
		virtualnetwork.Metadata{VMID: spec.VMID, NetworkID: spec.NetworkID},
	)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Session{
		ctx:     lifetimeCtx,
		cancel:  cancel,
		flows:   flows,
		network: network,
		runDone: make(chan struct{}),
	}, nil
}

func (s *Session) Run(ctx context.Context, conn net.Conn) error {
	if s == nil {
		return errors.New("session is not configured")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("session has already been started")
	}
	if s.closed {
		s.mu.Unlock()
		return conn.Close()
	}
	s.started = true
	s.conn = conn
	s.mu.Unlock()

	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	err := s.network.Run(s.ctx, conn)
	stop()
	_ = s.Close()

	s.mu.Lock()
	close(s.runDone)
	s.mu.Unlock()
	return err
}

func (s *Session) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	drainErr := s.flows.Wait(ctx)
	closeErr := s.Close()
	if err := s.wait(ctx); err != nil && drainErr == nil {
		drainErr = err
	}
	return errors.Join(drainErr, closeErr)
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		conn := s.conn
		s.mu.Unlock()
		s.cancel()
		if conn != nil {
			s.closeErr = conn.Close()
		}
		if err := s.network.Close(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

func (s *Session) wait(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	done := s.runDone
	s.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
