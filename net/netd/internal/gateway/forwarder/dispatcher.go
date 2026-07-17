package forwarder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
)

type TCPHandler interface {
	ShouldHandle(flow hooks.Flow, decision hooks.RouteDecision) bool
	HandleTCP(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, decision hooks.RouteDecision) error
}

type registeredTCPHandler struct {
	endpointType string
	handler      TCPHandler
}

type TCPDispatcher struct {
	handlers []registeredTCPHandler
}

func NewBuiltinTCPDispatcher(route *router.Router, certPath string, keyPath string, manager *credentials.Manager) (*TCPDispatcher, error) {
	dispatcher := &TCPDispatcher{}
	httpsProxy, err := NewHTTPSProxy(route, certPath, keyPath, manager)
	if err != nil {
		return nil, err
	}
	var ca *certificateAuthority
	if httpsProxy != nil {
		ca = httpsProxy.ca
	} else if route != nil && route.HasRegistries() {
		ca, err = loadCertificateAuthority(certPath, keyPath)
		if err != nil {
			return nil, err
		}
	}
	if httpProxy := NewHTTPProxy(route); httpProxy != nil {
		if err := dispatcher.Register("http", httpProxy); err != nil {
			return nil, err
		}
	}
	registryProxy, err := NewRegistryProxy(route, ca, httpsProxy)
	if err != nil {
		return nil, err
	}
	if registryProxy != nil {
		if err := dispatcher.Register("registries", registryProxy); err != nil {
			return nil, err
		}
	}
	if httpsProxy != nil {
		if err := dispatcher.Register("https", httpsProxy); err != nil {
			return nil, err
		}
	}
	return dispatcher, nil
}

func (d *TCPDispatcher) Register(endpointType string, handler TCPHandler) error {
	if d == nil {
		return fmt.Errorf("register TCP handler %q on nil dispatcher", endpointType)
	}
	if endpointType == "" {
		return fmt.Errorf("TCP handler endpoint type is required")
	}
	if handler == nil {
		return fmt.Errorf("TCP handler %q is nil", endpointType)
	}
	for _, registered := range d.handlers {
		if registered.endpointType == endpointType {
			return fmt.Errorf("TCP handler %q is already registered", endpointType)
		}
	}
	d.handlers = append(d.handlers, registeredTCPHandler{endpointType: endpointType, handler: handler})
	return nil
}

func (d *TCPDispatcher) Handle(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, decision hooks.RouteDecision) (string, bool, error) {
	if d == nil {
		return "", false, nil
	}
	eligible := make([]registeredTCPHandler, 0, len(d.handlers))
	for _, registered := range d.handlers {
		if registered.handler.ShouldHandle(flow, decision) {
			eligible = append(eligible, registered)
		}
	}
	if hasEndpointType(eligible, "http") && hasTLSEndpoint(eligible) {
		isTLS, replayed, err := sniffTLSRecord(inbound)
		if err != nil {
			_ = replayed.Close()
			return "dispatcher", true, err
		}
		inbound = replayed
		eligible = matchingProtocolHandlers(eligible, isTLS)
	}
	for _, registered := range eligible {
		return registered.endpointType, true, registered.handler.HandleTCP(ctx, inbound, flow, target, decision)
	}
	return "", false, nil
}

func hasEndpointType(handlers []registeredTCPHandler, endpointType string) bool {
	for _, handler := range handlers {
		if handler.endpointType == endpointType {
			return true
		}
	}
	return false
}

func hasTLSEndpoint(handlers []registeredTCPHandler) bool {
	return hasEndpointType(handlers, "registries") || hasEndpointType(handlers, "https")
}

func matchingProtocolHandlers(handlers []registeredTCPHandler, isTLS bool) []registeredTCPHandler {
	matched := make([]registeredTCPHandler, 0, len(handlers))
	for _, handler := range handlers {
		if handler.endpointType == "http" {
			if !isTLS {
				matched = append(matched, handler)
			}
			continue
		}
		if handler.endpointType == "registries" || handler.endpointType == "https" {
			if isTLS {
				matched = append(matched, handler)
			}
			continue
		}
		matched = append(matched, handler)
	}
	return matched
}

func sniffTLSRecord(conn net.Conn) (bool, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var first [1]byte
	n, err := io.ReadFull(conn, first[:])
	replayed := &replayConn{Conn: conn, reader: bytes.NewReader(first[:n])}
	if err != nil {
		return false, replayed, err
	}
	return first[0] == 0x16, replayed, nil
}
