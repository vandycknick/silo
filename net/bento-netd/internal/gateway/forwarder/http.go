package forwarder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/router"
)

const httpPort uint16 = 80

type HTTPProxy struct {
	route *router.Router
}

func NewHTTPProxy(route *router.Router) *HTTPProxy {
	if route == nil || !route.HasHTTP() {
		return nil
	}
	return &HTTPProxy{route: route}
}

func (p *HTTPProxy) ShouldHandle(port uint16) bool {
	return p != nil && p.route.HasHTTP() && port == httpPort
}

func (p *HTTPProxy) Handle(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string) error {
	defer inbound.Close()

	reader := bufio.NewReader(inbound)
	for {
		req, err := http.ReadRequest(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.Host == "" {
			_ = req.Body.Close()
			return writeHTTPStatus(inbound, http.StatusBadRequest, "missing_host")
		}

		decision, err := p.route.DecideHTTP(ctx, hooks.HTTPRequest{
			Flow:         flow,
			EndpointKind: "http",
			Host:         req.Host,
			Method:       req.Method,
			Path:         requestPath(req),
			Query:        req.URL.RawQuery,
			Header:       req.Header.Clone(),
		})
		if err != nil {
			_ = req.Body.Close()
			return err
		}
		if decision.Action == hooks.RouteDeny {
			_ = req.Body.Close()
			return writeDeny(inbound, decision.Reason)
		}

		if err := proxyPlainHTTPRequest(inbound, target, req); err != nil {
			return err
		}
		if req.Close {
			return nil
		}
	}
}

func proxyPlainHTTPRequest(client net.Conn, target string, req *http.Request) error {
	outbound, err := net.Dial("tcp", target)
	if err != nil {
		_ = req.Body.Close()
		return writeHTTPStatus(client, http.StatusBadGateway, "upstream_error")
	}
	defer outbound.Close()

	upstreamReader := bufio.NewReader(outbound)
	prepareForwardRequest(req, "http", req.Host)
	if err := req.Write(outbound); err != nil {
		_ = req.Body.Close()
		return err
	}

	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := resp.Write(client); err != nil {
		return err
	}
	return nil
}

func requestPath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func prepareForwardRequest(req *http.Request, scheme string, host string) {
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = scheme
	}
	if req.URL.Host == "" {
		req.URL.Host = host
	}
}

func writeDeny(conn net.Conn, reason string) error {
	if reason == "" {
		reason = "request denied by network policy"
	}
	return writeHTTPStatus(conn, http.StatusForbidden, reason)
}

func writeHTTPStatus(conn net.Conn, status int, body string) error {
	if body == "" {
		body = http.StatusText(status)
	}
	_, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	return err
}
