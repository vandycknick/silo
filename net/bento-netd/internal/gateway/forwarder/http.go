package forwarder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/router"
)

type HTTPProxy struct {
	route *router.Router
}

func NewHTTPProxy(route *router.Router) *HTTPProxy {
	if route == nil || !route.HasHTTP() {
		return nil
	}
	return &HTTPProxy{route: route}
}

func (p *HTTPProxy) ShouldHandle(flow hooks.Flow, decision hooks.RouteDecision) bool {
	return p != nil && decision.Action == hooks.RouteClassify && p.route.ShouldInterceptHTTP(flow.DestPort)
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
		request := httpRequest(flow, "http", req)
		if req.Host == "" {
			_ = req.Body.Close()
			status, body := http.StatusBadRequest, "missing_host"
			p.route.RecordHTTP(request, deniedFlow(body), status, httpStatusHeader(status, body))
			return writeHTTPStatus(inbound, status, body)
		}
		if p.route.MatchHTTPHost(req.Host) && !p.route.MatchHTTPHostForPort(req.Host, flow.DestPort) {
			_ = req.Body.Close()
			status, body := http.StatusMisdirectedRequest, "host_mismatch"
			p.route.RecordHTTP(request, deniedFlow(body), status, httpStatusHeader(status, body))
			return writeHTTPStatus(inbound, status, body)
		}

		decision, err := p.route.DecideHTTP(ctx, request)
		if err != nil {
			_ = req.Body.Close()
			return err
		}
		if decision.Action == hooks.RouteDeny {
			_ = req.Body.Close()
			status, body := denyStatusAndBody(decision.Reason)
			p.route.RecordHTTP(request, decision, status, httpStatusHeader(status, body))
			return writeHTTPStatus(inbound, status, body)
		}

		upgrade := isWebSocketUpgrade(req)
		outcome, err := forwardHTTPFamilyRequest(ctx, inbound, reader, req, "http", req.Host, nil, decision.Credential, func() (net.Conn, error) {
			return net.Dial("tcp", target)
		})
		p.route.RecordHTTPOutcome(request, decision, outcome.status, outcome.responseHeader, outcome.reason)
		if err != nil {
			return err
		}
		if upgrade || req.Close {
			return nil
		}
	}
}

func httpRequest(flow hooks.Flow, scheme string, req *http.Request) hooks.HTTPRequest {
	return hooks.HTTPRequest{
		Flow:         flow,
		EndpointKind: scheme,
		Host:         req.Host,
		Method:       req.Method,
		Path:         requestPath(req),
		Query:        req.URL.RawQuery,
		Header:       req.Header.Clone(),
	}
}

func requestPath(req *http.Request) string {
	path := req.URL.Path
	if path == "" {
		return "/"
	}
	return path
}

func writeDeny(conn net.Conn, reason string) error {
	status, body := denyStatusAndBody(reason)
	return writeHTTPStatus(conn, status, body)
}

func denyStatusAndBody(reason string) (int, string) {
	if reason == "" {
		reason = "request denied by network policy"
	}
	return statusForReason(reason), reason
}

func writeHTTPStatus(conn net.Conn, status int, body string) error {
	if body == "" {
		body = http.StatusText(status)
	}
	_, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	return err
}

func httpStatusHeader(status int, body string) http.Header {
	if body == "" {
		body = http.StatusText(status)
	}
	return http.Header{
		"Connection":     {"close"},
		"Content-Length": {strconv.Itoa(len(body))},
		"Content-Type":   {"text/plain; charset=utf-8"},
	}
}
