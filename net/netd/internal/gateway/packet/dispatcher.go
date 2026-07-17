package packet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

type TCPHandler interface {
	ShouldHandle(flow hooks.Flow, decision hooks.RouteDecision) bool
	HandleTCP(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, decision hooks.RouteDecision) error
}

type EndpointType string

const (
	EndpointHTTP       EndpointType = "http"
	EndpointHTTPS      EndpointType = "https"
	EndpointRegistries EndpointType = "registries"
)

type registeredTCPHandler struct {
	endpointType EndpointType
	handler      TCPHandler
}

type TCPDispatcher struct {
	handlers []registeredTCPHandler
}

func NewTCPDispatcher() *TCPDispatcher {
	return &TCPDispatcher{}
}

func (d *TCPDispatcher) Register(endpointType EndpointType, handler TCPHandler) error {
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

func (d *TCPDispatcher) Handle(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, decision hooks.RouteDecision) (EndpointType, bool, error) {
	if d == nil {
		return "", false, nil
	}
	eligible := make([]registeredTCPHandler, 0, len(d.handlers))
	for _, registered := range d.handlers {
		if registered.handler.ShouldHandle(flow, decision) {
			eligible = append(eligible, registered)
		}
	}
	if hasEndpointType(eligible, EndpointHTTP) && hasTLSEndpoint(eligible) {
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

func hasEndpointType(handlers []registeredTCPHandler, endpointType EndpointType) bool {
	for _, handler := range handlers {
		if handler.endpointType == endpointType {
			return true
		}
	}
	return false
}

func hasTLSEndpoint(handlers []registeredTCPHandler) bool {
	return hasEndpointType(handlers, EndpointRegistries) || hasEndpointType(handlers, EndpointHTTPS)
}

func matchingProtocolHandlers(handlers []registeredTCPHandler, isTLS bool) []registeredTCPHandler {
	matched := make([]registeredTCPHandler, 0, len(handlers))
	for _, handler := range handlers {
		if handler.endpointType == EndpointHTTP {
			if !isTLS {
				matched = append(matched, handler)
			}
			continue
		}
		if handler.endpointType == EndpointRegistries || handler.endpointType == EndpointHTTPS {
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

type replayConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}
